import pytoniq
import base64
import bitarray
import tvm_valuetypes

data = 'te6cckEBAQEAWgAAsKekjtEZIlfvjFQIciZ2W2Pol0VhAAAAAAAAAAAAAAAAAABV8KC4aZHGIYs2wdGdSi6esM42ButIYpzSWqkWnmu1gNqBaceZA+rR4noI99celK1XpJEnXNoEOqmt'
decoded = base64.b64decode(data)
expected = 'p6SO0RkiV++MVAhyJnZbY+iXRWEAAAAAAAAAAAAAAAAAAFXwoLhpkcYhizbB0Z1KLp6wzjYG60hinNJaqRaea7WA2oFpx5kD6tHiegj31x6UrVekkSdcAA==\n'

cells = pytoniq.Cell.from_boc(decoded)
print(cells[0])

def func(cell: pytoniq.Cell):
    print(bitarray.bitarray(cell.data))
    print(base64.b64encode(cell.data))
    for c in cell.refs:
        func(c)

print(len(cells[0].data) % 8)
for c in cells:
    func(c)

import codecs
from tvm_valuetypes import deserialize_boc

msg_cell_boc = codecs.decode(codecs.encode(data, 'utf8'), 'base64')
message_cell = deserialize_boc(msg_cell_boc)
dcd = message_cell.data.data.tobytes()
legacy = codecs.decode(codecs.encode(dcd, 'base64'), "utf8")
print(legacy)
