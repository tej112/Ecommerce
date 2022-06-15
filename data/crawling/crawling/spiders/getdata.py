import scrapy


class DataSpider(scrapy.Spider):
    name = "getdata"
    start_urls = ['https://aksa.co/collections/earing',
                  'https://aksa.co/collections/nose-rings',
                  'https://aksa.co/collections/anklets',
                  'https://aksa.co/collections/bracelet',
                  'https://aksa.co/collections/pendant',
                  'https://aksa.co/collections/ring',
                  'https://aksa.co/collections/toerings',
                  'https://aksa.co/collections/sets']

    def parse(self, response):
        items = response.css('div.col-xl-3.col-lg-6.col-md-6.col-6')
        for item in items:
            price = item.css('span.current_price::text').get().split(" ")[1]
            name = item.css('h3.popup_cart_title')
            name = name.css('a::text').get()
            img = "https:" + item.css('img.popup_cart_image').attrib['src']
            try:
                yield {
                    'name': name,
                    'price': price,
                    'img_link': img,
                    'category': response.url.split("/")[-1]
                }
            except Exception as e:
                yield {
                    'error': e
                }
