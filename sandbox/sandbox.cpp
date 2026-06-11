#include "adnl/adnl-network-manager.h"
#include "adnl/adnl-node-id.hpp"
#include "adnl/adnl.h"
#include "crypto/vm/vm.h"
#include "keyring/keyring.h"
#include "quic/quic-sender.h"
#include "td/actor/coro_utils.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/OptionParser.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"
#include "vm/cp0.h"

#include "auto/tl/ton_api.h"
#include "auto/tl/ton_api_json.h"
#include "tl/tl_json.h"

class EchoCallback : public ton::adnl::Adnl::Callback {
 public:
  std::shared_ptr<std::vector<td::BufferSlice>> received_messages;

  explicit EchoCallback(std::shared_ptr<std::vector<td::BufferSlice>> msgs = nullptr)
      : received_messages(std::move(msgs)) {
  }

  void receive_message(ton::adnl::AdnlNodeIdShort, ton::adnl::AdnlNodeIdShort, td::BufferSlice data) override {
    LOG(ERROR) << "receive message message";
    if (received_messages) {
      received_messages->push_back(std::move(data));
    }
  }

  void receive_query(ton::adnl::AdnlNodeIdShort, ton::adnl::AdnlNodeIdShort, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    promise.set_value(std::move(data));
  }
};

ton::quic::QuicServer::Options quic_test_options() {
  ton::quic::QuicServer::Options options;
  options.flood_control.reset();
  options.new_connection_rate_limit_capacity = 0;
  return options;
}

ton::PrivateKey make_key(int seed) {
  td::Bits256 hash;
  auto seed_str = std::to_string(seed);
  td::sha256(td::Slice(seed_str), hash.as_slice());
  return ton::PrivateKey{ton::privkeys::Ed25519{hash}};
}

ton::adnl::AdnlAddressList make_addr_list(td::Slice ip_str, int port) {
  td::IPAddress ip;
  ip.init_host_port(PSTRING() << ip_str << ":" << port).ensure();
  ton::adnl::AdnlAddressList list;
  list.add_udp_adnl_address(ip).ensure();
  list.set_version(static_cast<td::int32>(td::Clocks::system()));
  list.set_reinit_date(ton::adnl::Adnl::adnl_start_time());
  return list;
}

struct TestNode {
  ton::adnl::AdnlNodeIdShort id;
  ton::PrivateKey key;
  std::string ip{"127.0.0.1"};
  int port{0};

  td::actor::ActorOwn<ton::keyring::Keyring> keyring;
  td::actor::ActorOwn<ton::adnl::AdnlNetworkManager> network_manager;
  td::actor::ActorOwn<ton::adnl::Adnl> adnl;
  td::actor::ActorOwn<ton::quic::QuicSender> quic_sender;
  std::shared_ptr<std::vector<td::BufferSlice>> received_messages;

  TestNode() = default;
  TestNode(TestNode&&) = default;
  TestNode& operator=(TestNode&&) = default;
};

struct RemoteFullNode {
  ton::adnl::AdnlNodeIdShort id;
  ton::PublicKey pubkey;
  std::string ip;
  int port;

  RemoteFullNode() = default;
  RemoteFullNode(RemoteFullNode&&) = default;
  RemoteFullNode& operator=(RemoteFullNode&&) = default;
};

class TestRunner : public td::actor::Actor {
 public:
  using TestFunc = std::function<td::actor::Task<td::Unit>(TestRunner&)>;
  TestRunner(std::string db_root, double timeout, TestFunc test) : db_root_(std::move(db_root)), timeout_(timeout), test_(test) {
  }

  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(timeout_);
    [](td::actor::Task<td::Unit> task) -> td::actor::Task<td::Unit> {
      (co_await std::move(task).wrap()).ensure();
      co_await td::actor::Yield{};
      td::actor::SchedulerContext::get().stop();
      co_return td::Unit{};
    }(test_(*this))
                                              .start_immediate()
                                              .detach("test");
  }

  void alarm() override {
    LOG(FATAL) << "Test timeout after " << timeout_ << "s";
  }

  td::actor::Task<TestNode> create_node(std::string name, int port, ton::PrivateKey key, std::string ip = "127.0.0.1") {
    TestNode node;
    node.ip = ip;
    node.port = port;
    node.key = key;
    node.id = ton::adnl::AdnlNodeIdShort{node.key.compute_public_key().compute_short_id()};

    std::string db = db_root_ + "/" + name;
    td::rmrf(db).ignore();
    td::mkdir(db).ensure();

    node.keyring = ton::keyring::Keyring::create(db);
    node.network_manager = ton::adnl::AdnlNetworkManager::create();
    node.adnl = ton::adnl::Adnl::create(db, node.keyring.get());

    td::actor::send_closure(node.adnl, &ton::adnl::Adnl::register_network_manager, node.network_manager.get());

    ton::adnl::AdnlCategoryMask cat_mask;
    cat_mask[0] = true;
    td::IPAddress addr;
    addr.init_host_port(PSTRING() << ip << ":" << port).ensure();
    td::actor::send_closure(node.network_manager, &ton::adnl::AdnlNetworkManager::add_self_addr, addr,
                            std::move(cat_mask), 0);

    co_await td::actor::ask(node.keyring, &ton::keyring::Keyring::add_key, node.key, true);

    auto addr_list = make_addr_list(ip, port);
    td::actor::send_closure(node.adnl, &ton::adnl::Adnl::add_id,
                            ton::adnl::AdnlNodeIdFull{node.key.compute_public_key()}, addr_list, td::uint8(0));

    td::actor::send_closure(node.adnl, &ton::adnl::Adnl::subscribe, node.id, "Q", std::make_unique<EchoCallback>());

    node.received_messages = std::make_shared<std::vector<td::BufferSlice>>();
    td::actor::send_closure(node.adnl, &ton::adnl::Adnl::subscribe, node.id, "M",
                            std::make_unique<EchoCallback>(node.received_messages));

    node.quic_sender = td::actor::create_actor<ton::quic::QuicSender>(
        "quic-" + name, td::actor::actor_dynamic_cast<ton::adnl::AdnlPeerTable>(node.adnl.get()), node.keyring.get(),
        quic_test_options());

    td::actor::send_closure(node.quic_sender, &ton::quic::QuicSender::add_id, node.id);

    co_await td::actor::Yield{};
    co_return std::move(node);
  }

  void add_peer(TestNode& from, const RemoteFullNode& to) {
    auto addr_list = make_addr_list(to.ip, to.port);
    td::actor::send_closure(from.adnl, &ton::adnl::Adnl::add_peer, from.id, ton::adnl::AdnlNodeIdFull{to.pubkey},
                            addr_list);
  }

  td::actor::Task<td::BufferSlice> send_query(TestNode& from, RemoteFullNode& to, td::Slice data) {
    td::BufferSlice query(1 + data.size());
    query.as_slice()[0] = 'Q';
    query.as_slice().substr(1).copy_from(data);

    auto [future, promise] = td::actor::StartedTask<td::BufferSlice>::make_bridge();
    td::actor::send_closure(from.quic_sender, &ton::quic::QuicSender::send_query, from.id, to.id, std::string("Q"),
                            std::move(promise), td::Timestamp::in(30.0), std::move(query));
    co_return co_await std::move(future);
  }

  td::actor::Task<td::BufferSlice> send_query_ex(TestNode& from, RemoteFullNode& to, td::Slice data, double timeout,
                                                 td::uint64 max_answer_size) {
    td::BufferSlice query(1 + data.size());
    query.as_slice()[0] = 'Q';
    query.as_slice().substr(1).copy_from(data);

    auto [future, promise] = td::actor::StartedTask<td::BufferSlice>::make_bridge();
    td::actor::send_closure(from.quic_sender, &ton::quic::QuicSender::send_query_ex, from.id, to.id, std::string("Q"),
                            std::move(promise), td::Timestamp::in(timeout), std::move(query), max_answer_size);
    co_return co_await std::move(future);
  }

 private:
  std::string db_root_;
  double timeout_;
  TestFunc test_;
};

struct Config {
  std::string ip{"127.0.0.1"};
  int port{20070};
  int threads{4};
  ton::PrivateKey key;

  ton::PublicKey remote_key;
  std::string remote_ip{"127.0.0.1"};
  int remote_port{20070};
  double timeout{60.0};
};

Config g_config;

int main(int argc, char* argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_DEBUG);
  td::set_default_failure_signal_handler().ensure();

  CHECK(vm::init_op_cp0());

  // params
  td::OptionParser p;
  p.set_description("Sandbox");
  p.add_checked_option('p', "port", "base port (default 21000)", [&](td::Slice arg) {
    TRY_RESULT(v, td::to_integer_safe<int>(arg));
    g_config.port = v;
    return td::Status::OK();
  });
  p.add_checked_option('t', "threads", "scheduler threads (default 4)", [&](td::Slice arg) {
    TRY_RESULT(v, td::to_integer_safe<int>(arg));
    g_config.threads = v;
    return td::Status::OK();
  });
  p.add_option('T', "timeout", "test timeout in seconds (default 60)",
               [](td::Slice arg) { g_config.timeout = td::to_double(arg); });
  p.add_checked_option('k', "key", "private key path", [&](td::Slice arg) {
    TRY_RESULT_PREFIX(data, td::read_file_secure(arg.str()), "failed to read private key: ");
    TRY_RESULT_PREFIX_ASSIGN(g_config.key, ton::PrivateKey::import(data.as_slice()), "failed to import private key: ");
    return td::Status::OK();
  });
  p.run(argc, argv).ensure();

  auto bytes = td::base64_decode("3lt1TGfkcWaBAImk0X9Dq6RM1BMwLIzvNcVQUuW8oiI=").move_as_ok();
  td::Bits256 raw;
  raw.as_slice().copy_from(td::Slice(bytes));
  auto adnl_key = ton::PublicKey{ton::pubkeys::Ed25519{raw}};
  // 3lt1TGfkcWaBAImk0X9Dq6RM1BMwLIzvNcVQUuW8oiI=
  // xrQTSN5bdUxn5HFmgQCJpNF/Q6ukTNQTMCyM7zXFUFLlvKIi

  LOG(INFO) << "Remote ADNL id: " << td::base64_encode(adnl_key.compute_short_id().as_slice());
  LOG(INFO) << "Remote ADNL key: " << "3lt1TGfkcWaBAImk0X9Dq6RM1BMwLIzvNcVQUuW8oiI=";

  g_config.remote_ip = "172.16.241.73";
  g_config.remote_port = (29887 + 1000) % 65536;

  std::string db_root = "dev-test-quic-sender";
  td::mkdir(db_root).ensure();

  LOG(INFO) << g_config.key.empty();

  auto test_ = [](TestRunner& t) -> td::actor::Task<td::Unit> {
    auto node = co_await t.create_node("node", g_config.port, g_config.key);
    RemoteFullNode remote;
    remote.id = ton::adnl::AdnlNodeIdShort{g_config.remote_key.compute_short_id()};
    remote.pubkey = g_config.remote_key;
    remote.ip = g_config.remote_ip;
    remote.port = g_config.remote_port;
  };

  td::actor::Scheduler scheduler({g_config.threads});
  scheduler.run_in_context([&] { td::actor::create_actor<TestRunner>("test", db_root, g_config.timeout, std::move(test_)).release(); });
  scheduler.run();

  // run_test([](TestRunner& t) -> td::actor::Task<td::Unit> {
  //   auto a = co_await t.create_node("a", g_config.port);
  //
  //   auto resp1 = co_await t.send_query(a, b, "a-to-b");
  //   ASSERT_EQ(resp1.as_slice(), td::Slice("Qa-to-b"));
  //
  //   co_return td::Unit{};
  // });
}
