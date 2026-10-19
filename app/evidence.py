"""Observed evidence for PRD checks. Evidence is separate from model confidence."""
import re
import unicodedata
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit
from .providers import url_inputs
from .schemas import Finding

# Public canonical domains used to describe a resemblance, never to guarantee safety.
BRANDS = {'paypal':'paypal.com','google':'google.com','microsoft':'microsoft.com','apple':'apple.com','amazon':'amazon.com','netflix':'netflix.com'}
CONFUSABLES = str.maketrans({'0':'o','1':'l','3':'e','5':'s','а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','і':'i','ӏ':'l','у':'y'})

class Anchors(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.href=None; self.words=[]; self.pairs=[]
    def handle_starttag(self,tag,attrs):
        if tag=='a': self.href=dict(attrs).get('href'); self.words=[]
    def handle_data(self,data):
        if self.href: self.words.append(data)
    def handle_endtag(self,tag):
        if tag=='a' and self.href:
            self.pairs.append((''.join(self.words).strip(),self.href)); self.href=None

def domain(url):
    try: return (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError: return ''

def under(host, official): return host==official or host.endswith('.'+official)

def inspect_evidence(request, urls):
    found=[]
    def add(code,message,severity='warning'):
        found.append(Finding(code=code,message=message,weight=0,source='observed',severity=severity))
    for url in urls:
        host=domain(url)
        try: decoded=host.encode('ascii').decode('idna')
        except (UnicodeError,UnicodeDecodeError): decoded=host
        labels=decoded.split('.')[:-1]
        for brand,official in BRANDS.items():
            if under(host,official): continue
            # Exact brand fragments, character substitutions and one added/removed digit.
            for label in labels:
                normalized=unicodedata.normalize('NFKC',label).casefold().translate(CONFUSABLES)
                digitless=re.sub(r'\d','',label.casefold())
                if (brand in label.casefold() or normalized==brand or digitless==brand):
                    add('brand_lookalike',f'The address {host} resembles {brand.title()}, but it is not under {official}. Confirm the sender independently.')
                    break
            else: continue
            break
        if any(ord(c)>127 for c in decoded):
            add('international_domain','The address contains international characters. Similar-looking letters can be misleading; check the full address.','notice')
        try:
            parts=urlsplit(url)
            if parts.username is not None: add('embedded_credentials','The address contains an @ sign before the website name. The website is the part after that sign.')
        except ValueError: pass
    for code,pattern,message in [
        ('urgency',r'\b(act now|immediately|urgent|account suspended|last warning)\b','The message pressures you to act quickly.'),
        ('sensitive_request',r'\b(send|share|provide|verify|confirm|enter)\b.{0,60}\b(password|bank details|one.time code|recovery phrase)\b','The message asks about sensitive login or financial information. Confirm the request separately.'),
        ('gift_card_request',r'\b(buy|purchase|send)\b.{0,50}\bgift cards?\b','The message asks for gift cards, a payment method commonly requested in scams.'),
        ('secrecy',r'\b(keep (?:this )?confidential|keep (?:this )?secret|do not call|don.t call)\b','The message discourages independent checking.'),
    ]:
        if re.search(pattern,request.content,re.I): add(code,message)
    if request.sender and request.reply_to:
        sender=parseaddr(request.sender)[1].rsplit('@',1)
        reply=parseaddr(request.reply_to)[1].rsplit('@',1)
        if len(sender)==len(reply)==2 and sender[1].casefold()!=reply[1].casefold():
            add('reply_to_mismatch','Replies go to a different domain from the sender. This can be legitimate, but needs checking.')
    if request.sender:
        display,address=parseaddr(request.sender)
        host=address.rsplit('@',1)[-1].lower()
        for brand,official in BRANDS.items():
            if brand in display.casefold() and not under(host,official):
                add('sender_brand_mismatch',f'The sender name mentions {brand.title()}, but its email domain is not {official}. Sender identity has not been authenticated.')
                break
    parser=Anchors(); parser.feed(request.content)
    pairs=parser.pairs+re.findall(r'\[([^\]]+)\]\((https?://[^\s)]+)\)',request.content)
    for visible,target in pairs:
        shown=url_inputs(visible)
        if shown and domain(shown[0]) and domain(target) and domain(shown[0])!=domain(target):
            add('misleading_link_text','The displayed website address differs from the actual link destination.')
    return list({(item.code,item.message):item for item in found}.values())
