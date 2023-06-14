/*
    This file is part of TON Blockchain Library.
    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.
    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
    Copyright 2017-2020 Telegram Systems LLP
*/
#pragma once

#if !TDDB_USE_ROCKSDB
#error "RocksDb is not supported"
#endif

#include "td/db/KeyValue.h"
#include "td/utils/Status.h"

namespace rocksdb {
class DB;
class Transaction;
class WriteBatch;
class Snapshot;
class Statistics;
}  // namespace rocksdb

namespace td {
class RocksDbSecondary : public KeyValue {
 public:
  static Status destroy(Slice path);
  RocksDbSecondary clone() const;
  static Result<RocksDbSecondary> open(std::string path);

  Status try_catch_up_with_primary();

  Result<GetStatus> get(Slice key, std::string &value) override;
  Status set(Slice key, Slice value) override;
  Status erase(Slice key) override;
  Result<size_t> count(Slice prefix) override;

  Status begin_write_batch() override;
  Status commit_write_batch() override;
  Status abort_write_batch() override;

  Status begin_transaction() override;
  Status commit_transaction() override;
  Status abort_transaction() override;
  Status flush() override;

  Status begin_snapshot();
  Status end_snapshot();

  std::unique_ptr<KeyValueReader> snapshot() override;
  std::string stats() const override;

  RocksDbSecondary(RocksDbSecondary &&);
  RocksDbSecondary &operator=(RocksDbSecondary &&);
  ~RocksDbSecondary();

  std::shared_ptr<rocksdb::DB> raw_db() const {
    return db_;
  };

 private:
  std::shared_ptr<rocksdb::DB> db_;
  std::shared_ptr<rocksdb::Statistics> statistics_;

  std::unique_ptr<rocksdb::Transaction> transaction_;
  std::unique_ptr<rocksdb::WriteBatch> write_batch_;
  class UnreachableDeleter {
   public:
    template <class T>
    void operator()(T *) {
      UNREACHABLE();
    }
  };
  std::unique_ptr<const rocksdb::Snapshot, UnreachableDeleter> snapshot_;

  explicit RocksDbSecondary(std::shared_ptr<rocksdb::DB> db,
                   std::shared_ptr<rocksdb::Statistics> statistics);
};
}  // namespace td
