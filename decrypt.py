records = [
    '5c69e5c11a0794fe6016d7ba1c98bd4b5b6bf09f0a52',
    '5c69e5c11a0794fe7a02dcaf1c98bd4b5b6bf09f0a52',
    '5c69e5c11a0794fe721ed0b51c98bd4b5b6bf09f0a52',
    '5c69e5c11a0794fe7b16d0b21c98bd4b5b6bf09f0a52',
    '5c69e5c11a0794fe7a16d8a21c98bd4b5b6bf09f0a52',
]
key = bytes.fromhex('341d91b1693dbbd10877bed632fbd228')
for i, r in enumerate(records):
    data = bytes.fromhex(r)
    decrypted = bytes(data[j] ^ key[j % 16] for j in range(22))
    print(f'Record {i}: {decrypted.decode("utf-8")}')