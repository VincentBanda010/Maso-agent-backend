from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
s=getSampleStyleSheet()
s.add(ParagraphStyle(name='TitleM',fontName='Helvetica-Bold',fontSize=30,leading=34,textColor=colors.HexColor('#102C3C'),spaceAfter=10))
s.add(ParagraphStyle(name='IntroM',fontSize=11,leading=16,textColor=colors.HexColor('#425768'),spaceAfter=14))
s.add(ParagraphStyle(name='HeadM',fontName='Helvetica-Bold',fontSize=13,leading=17,textColor=colors.HexColor('#102C3C'),spaceAfter=8))
s.add(ParagraphStyle(name='BodyM',fontSize=10,leading=14,textColor=colors.HexColor('#263D4A'),spaceAfter=8))
s.add(ParagraphStyle(name='SampleM',fontName='Courier',fontSize=9,leading=13,wordWrap='CJK'))
P=lambda t,style='BodyM':Paragraph(escape(t).replace('\n','<br/>'),s[style])
flow=[]
def header(title,sub):
 flow.extend([P('MASO  /  DEMO & TEST GUIDE','IntroM'),P(title,'TitleM'),P(sub,'IntroM')])
def case(num,title,text,expected):
 box=Table([[P(text,'SampleM')]],colWidths=[475])
 box.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#F0F5F7')),('BOX',(0,0),(-1,-1),0.6,colors.HexColor('#D9E4E9')),('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]))
 flow.append(KeepTogether([P(f'{num:02d}  {title}','HeadM'),box,Spacer(1,8),P('Expected: '+expected),Spacer(1,14)]))
header('Meet Maso','Your AI link safety buddy. Check before you click.')
flow.append(P('A delivery text, a payment request or a QR code can look ordinary and still lead to a scam. Maso helps you check a link or message before you act on it. You can paste text or attach an email file or QR image.'))
flow.append(P('What Maso gives you','HeadM'))
flow.append(P('A short safety result, the checks that were completed, and a practical next step. It is designed for everyday people, with no security knowledge needed.'))
flow.append(Spacer(1,8))
flow.append(P('The tools behind the check','HeadM'))
for title,desc in [
 ('Message AI: BERT','Looks for scam-like language in messages and email text. The model is ElSlay/BERT-Phishing-Email-Model, available through Hugging Face, a library of AI models.'),
 ('Link AI: URLBERT','Examines the written web address for patterns learned from examples. The model is CrabInHoney/urlbert-tiny-v4-phishing-classifier. It does not read the website itself.'),
 ('OpenPhish Community','Provides a list of reported phishing links. Phishing means trying to trick someone into giving away private information. Maso downloads this list and compares submitted links on the computer hosting Maso; it does not send them to OpenPhish. The list refreshes every 12 hours.'),
 ('QR reader: OpenCV','Reads the web address hidden inside a QR image, so Maso can check it like a pasted link.'),
 ('The app: React, Vite and FastAPI','React and Vite provide the screen you use. FastAPI connects it to the checks. Hugging Face Transformers and PyTorch run the AI models on the computer hosting Maso.')]:
 flow.extend([P(title,'HeadM'),P(desc)])
flow.append(P('Two different kinds of evidence','HeadM'))
flow.append(P('AI estimates risk from learned patterns. OpenPhish can confirm that an exact link appears on its reported-threat list. A link missing from that list is not automatically safe, and AI can make mistakes.'))
flow.append(PageBreak())
header('How Maso works','Paste it. Check it. Read the result. Decide your next step.')
for title,desc in [
 ('1. Add what you received','Paste a link or message, or use the attachment button for an .eml email file or a QR image.'),
 ('2. Let Maso check it','The message AI checks the words, and the link AI checks any extracted web addresses. With OpenPhish enabled, Maso also compares links against the downloaded list.'),
 ('3. Read the result','Low risk means the checks found less cause for concern; it is not a promise of safety. Suspicious or high risk means pause and verify. An OpenPhish match means the link is reported as harmful.'),
 ('4. Follow the next step','For a risky request, stop before clicking, paying or sharing details. Contact the organisation using a phone number or app you already trust.')]:
 flow.extend([P(title,'HeadM'),P(desc),Spacer(1,5)])
flow.append(P('A simple demonstration','HeadM'))
flow.append(P('Before you start: Keep Maso running, open its page, and enable "Check OpenPhish scam reports". Use the sample numbers on the following pages.'))
for title,desc in [
 ('Start with an ordinary message - test 5','Show how someone submits a message and reads a short result.'),
 ('Try an urgent scam message - test 4 or 6','Show the warning and next step. Check that the AI actually completed the check.'),
 ('Prove OpenPhish is working - test 1','Paste the reported link into Maso only. Look for an Unsafe result that names OpenPhish. A warning from AI alone does not prove this part worked.'),
 ('Show a QR image or email - test 9 or 10','Prepare the file beforehand. Attach it, submit it and explain the result.'),
 ('Finish with the limits','Explain that a new scam may not be listed yet. The AI and reported-link check help people decide, but neither guarantees safety.')]:
 flow.extend([P(title,'HeadM'),P(desc)])
flow.append(PageBreak())
header('Links & live reports','Copy one sample at a time into Maso. Enable "Check OpenPhish scam reports" for link tests.')
flow.append(P('Safety: Paste reported phishing links into Maso only. Do not open them. These links were retrieved on 19 October 2026; feed entries can change.'))
case(1,'Known phishing link','http://xunqelo-mpt-favzari-h4d8me63.pages.dev/','Unsafe, clearly linked to an OpenPhish report if the link remains listed. A model-only Dangerous verdict does not prove OpenPhish worked.')
case(2,'Normal website','https://www.google.com/','The link AI and OpenPhish lookup complete. No feed match must not be described as proof of safety.')
case(3,'Made-up lookalike address','https://paypa1.example/login','The link AI runs. This is a reserved example address, not a confirmed scam or a guaranteed OpenPhish match.')
flow.append(P('Other reported links from the same feed:','HeadM'))
flow.append(P('http://sp23ct-ravem-biz-zulok-pelun.pages.dev/\nhttp://zunqari-mpt-xavfelo-h6d4pe82.pages.dev/','SampleM'))
flow.append(PageBreak())
header('Messages & mixed content','These made-up messages test model behaviour. The expected labels are targets to evaluate, not guaranteed predictions.')
case(4,'Urgent account scam','Your account will be suspended in 15 minutes. Reply with your password and the verification code we just sent you to keep your account active.','The message AI runs and should flag suspicious or high risk. No link means no OpenPhish lookup is needed.')
case(5,'Ordinary message','Hi, our meeting starts at 10 tomorrow. Please bring your notebook. No payment or account action is required.','The message AI runs and should return low risk.')
case(6,'Gift-card scam',"I'm in a meeting and cannot talk. Buy five gift cards worth R1,000 each and send me photos of the codes immediately. Keep this confidential. I will reimburse you.",'The message AI should flag suspicious or high risk.')
case(7,'Message with a reported link','Your delivery is on hold. Confirm your details immediately:\nhttp://xunqelo-mpt-favzari-h4d8me63.pages.dev/','Both message and embedded link are checked. An active OpenPhish match produces Unsafe with OpenPhish named as the reason.')
flow.append(PageBreak())
header('Multiple links & uploads','For uploads, prepare the image or email file described below. This PDF itself is not a supported test upload.')
case(8,'Two links in one message','Please check these:\nhttps://www.google.com/\nhttp://xunqelo-mpt-favzari-h4d8me63.pages.dev/','Both links are extracted. A confirmed feed match makes the overall result Unsafe regardless of the other link\'s model score.')
case(9,'QR image','QR content:\nhttp://xunqelo-mpt-favzari-h4d8me63.pages.dev/','Create a QR image containing the URL only, then attach it. Maso must decode and check the URL, with OpenPhish attribution if listed.')
flow.append(P('10  Email file','HeadM'))
flow.append(P('Save the following as plain text named scam-test.eml. Preserve the blank line before the body, then attach the file. Do not send the email.'))
email='From: "Company Director" <director@example.com>\nReply-To: payments@example.net\nTo: employee@example.org\nSubject: Urgent confidential purchase\nMIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n\nBuy five gift cards worth R1,000 each immediately.\nReply with photos of the codes. Keep this confidential.'
b=Table([[P(email,'SampleM')]],colWidths=[475]);b.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#F0F5F7')),('LEFTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]));flow.extend([b,Spacer(1,8),P('Expected: Email content reaches the model and should be flagged. Automatic checks for different sender and reply addresses are not yet fully connected.')])
flow.append(PageBreak())
header('Boundaries & results','Use this page to distinguish a completed check from a plausible-looking answer.')
case(11,'Outside Maso\'s purpose','Write a romantic poem about the moon.','A brief explanation that Maso checks links, messages, emails and QR codes for scams.')
case(12,'Invalid input','Try separately:\n- An empty submission\n- An unsupported file type\n- An image without a readable QR code','A helpful error or blocked submission. Never a Safe verdict for input that was not checked.')
flow.append(P('Record each test','HeadM'))
rows=[['Test','Verdict','AI finished?','OpenPhish check','Pass / Fail']]+[[str(i),'','','',''] for i in range(1,13)]
t=Table(rows,colWidths=[35,90,100,160,90],rowHeights=[24]+[18]*12)
t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#102C3C')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),9),('GRID',(0,0),(-1,-1),0.4,colors.HexColor('#D4DFE5')),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
flow.extend([t,Spacer(1,12),P('Record OpenPhish as: matched, no match, unavailable, or not needed. Keep unexpected model results as failures to investigate.'),P('Coverage limits: This pack tests functionality. It does not establish how reliably it catches scams or completion of every project requirement. Response time, handling many users at once and privacy need separate checks.')])
def footer(c,d):
 c.setStrokeColor(colors.HexColor('#D9E4E9'));c.line(60,43,535,43);c.setFont('Helvetica',8);c.setFillColor(colors.HexColor('#607483'));c.drawString(60,30,'MASO  |  Test before you trust');c.drawRightString(535,30,str(d.page))
out=Path('output/pdf/Maso-Frontend-Test-Pack.pdf')
SimpleDocTemplate(str(out),pagesize=A4,rightMargin=60,leftMargin=60,topMargin=45,bottomMargin=58,title='Maso Demo and Test Guide',author='Maso').build(flow,onFirstPage=footer,onLaterPages=footer)



