import requests

url = "http://craphound.com/images/1006884_2adf8fc7.jpg"
response = requests.get(url)
if response.status_code == 200:
    with open("sample.jpg", 'wb') as f:
        print(type(response.content))
        content = response.content
        content = str(content)
        print(type(content))
        content = ' '.join(format(ord(x), 'b') for x in content)
        print(type(content))
        f.write(content.encode('utf-8'))