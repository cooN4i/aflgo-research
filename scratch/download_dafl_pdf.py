import urllib.request

for name, url in [('dafl_paper.pdf', 'https://www.usenix.org/system/files/usenixsecurity23-kim-tae-eun.pdf'),
                  ('dafl_appendix.pdf', 'https://www.usenix.org/system/files/usenixsecurity23-appendix-kim-tae-eun.pdf')]:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    data = urllib.request.urlopen(req).read()
    with open(f'scratch/{name}', 'wb') as f:
        f.write(data)
    print(f'{name}: {len(data)} bytes')

