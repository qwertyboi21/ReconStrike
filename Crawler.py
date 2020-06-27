import requests    
import re    
from urllib.parse import urlparse    
import os    

print("When You have enough info, press Ctrl+C")
site = input("Please enter the site you want to crawl (Ex. https://google.com/): ")



class PyCrawler(object):    
    def __init__(self, starting_url):    
        self.starting_url = starting_url    
        self.visited = set()    
        self.proxy_orbit_key = os.getenv("PROXY_ORBIT_TOKEN")    
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"    
        self.proxy_orbit_url = f"https://api.proxyorbit.com/v1/?token={self.proxy_orbit_key}&ssl=true&rtt=0.3&protocols=http&lastChecked=30"    

    def get_html(self, url):                                                                                                               
        try:                                                                                                                                                                                                                            
            html = requests.get(url, headers={"User-Agent":self.user_agent}, timeout=5)        
        except Exception as e:                                                                                                        
            print(e)                                                                                                                  
            return ""                                                                                                                 
        return html.content.decode('latin-1')                                                                                         

    def get_links(self, url):    
        html = self.get_html(url)    
        parsed = urlparse(url)    
        base = f"{parsed.scheme}://{parsed.netloc}"    
        links = re.findall('''<a\s+(?:[^>]*?\s+)?href="([^"]*)"''', html)    
        for i, link in enumerate(links):    
            if not urlparse(link).netloc:    
                link_with_base = base + link    
                links[i] = link_with_base    

        return set(filter(lambda x: 'mailto' not in x, links))    

    def extract_info(self, url):    
        html = self.get_html(url)    
        meta = re.findall("<meta .*?name=[\"'](.*?)['\"].*?content=[\"'](.*?)['\"].*?>", html)    
        return dict(meta)    

    def crawl(self, url):    
        for link in self.get_links(url):    
            if link in self.visited:    
                continue    
            self.visited.add(link)    
            info = self.extract_info(link)    

            print(f"""Link: {link}    
Description: {info.get('description')}    
Keywords: {info.get('keywords')}    
            """)    

            self.crawl(link)    

    def start(self):    
        self.crawl(self.starting_url)    

if __name__ == "__main__":    
    crawler = PyCrawler(site)    
    crawler.start()
