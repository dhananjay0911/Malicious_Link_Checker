import re

def validate_url(url):
    regex=re.compile(
        r'^(https?://)?'
        r'(www\.)?'
        r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}'

    )

    return re.match(regex,url) is not None