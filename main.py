from url_checker import check_url
from utils import validate_url

def main():
    print("welcome to the Malicious URL Checker!")

    url=input("Enter a URL to check: ").strip();

    if not validate_url(url):
        print("Invalid URL format. Please try again.")
        return
    
    result=check_url(url)

    print(f"Result:{result}")


if __name__=="__main__":
    main()
