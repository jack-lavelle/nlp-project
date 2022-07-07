import requests
import json
import re
import pymssql
import pandas as pd
import numpy as np
import keyring
from IPython.display import display
import fpdf
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pgf import PdfPages
from PyPDF2 import PdfFileMerger
import os
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import smtplib  
import email.utils
pd.options.mode.chained_assignment = None
import pymsteams
from tabulate import tabulate
import math

#To future reader, start at the monitor() function as it is where my program starts and it is most easily understood in chronological order.

def toPDF(eventid, df, myTeamsMessage):
    #This is the most complex part of the code and one that I would love to overhaul and clean it up properly.

    #To start, I read the dataframe and get relevant information from each row corresponding to each NOE and group them in lists. 
    rowNumber = len(df.index)
    eventids = []
    eoes = []
    similiarities = []

    for number in range(rowNumber):
        row = df.iloc[number]
        currentid = row['EVENTID'].encode('latin-1', 'replace').decode('latin-1')
        manager = row['NOE2_AREA_MANAGER'].encode('latin-1', 'replace').decode('latin-1')
        initiator = row['NOE2_NOE_INITIATOR'].encode('latin-1', 'replace').decode('latin-1')
        topic = row['NOE2_TOPIC'].encode('latin-1', 'replace').decode('latin-1')
        solution = row['NOE2_NOE_CORRECTIVE_ACTION']
        if solution is not None:
            solution = solution.encode('latin-1', 'replace').decode('latin-1')
        eoe = row['NOE2_EOE_REQUIRED']
        sim = row['Similarity']
        
        eventids.append(currentid)
        eoes.append(eoe)
        similiarities.append(sim)
    
    #Create new dataframe with the lists of metadata just made.
    tabdf = pd.DataFrame(eventids)
    tabdf.columns = ['EVENT-ID']
    tabdf['EOE Required?'] = eoes
    tabdf['Similarity'] = similiarities
    tabdf['Similarity'] = pd.to_numeric(tabdf['Similarity'])
    tabdf = tabdf[tabdf.Similarity >= 0.9] #remove sufficiently dissimiliar NOEs

    #Next connect to the main database that contains all the NOEs and query for them. 
    #This is my least favorite part of my program as I load all the NOEs and all of their metadata ... making it very slow. Another area to fix had I time enough.
    conn = pymssql.connect(server="RHNALON15SQL03D", user="REGENERON\s.jack.lavelle", password=keyring.get_password("RHNSQL_s.jack", "s.jack.lavelle"), database="IOPS_Data_Warehouse")
    cursor = conn.cursor()
    query = """
        SELECT * FROM [IOPS_Data_Warehouse].[QProcess].[EventSearch_NOE]
        """

    results = cursor.execute(query)
    #searchdf is the dataframe made from converting the SQL query to a dataframe ... it contains all the NOEs.
    searchdf = pd.read_sql_query(query, conn)
    conn.close()

    #next the pdf generation starts. see the documentation for fpdf.
    pdf = fpdf.FPDF(format='letter')
    pdf.add_page()
    pdf.set_font("Times", style = 'B', size = 14)
    pdf.write(5, "%s REPORT\n\n" % eventid)
    pdf.set_font("Times", size = 12)

    #the message that is sent in an email to the initiator is started.
    myEmailMessage = "There were %s closely related NOEs with " % len(tabdf.index)
    pdf.write(5, "There were %s closely related NOEs with " % len(tabdf.index))
    numclsnoe = len(tabdf.index)

    #next we look into the escalation rates by looking at whether or not an EOE was required.
    tabdf = tabdf.loc[tabdf['EOE Required?'] == 'Yes']
    numeoe = len(tabdf.index)
    eoetonoe = numeoe/numclsnoe

    myEmailMessage = myEmailMessage + "an NOE to EOE escalation rate of %.2s percent. " % (eoetonoe * 100)
    pdf.write(5, "an NOE to EOE escalation rate of %.2s percent. " % (eoetonoe * 100))

    #next I take the eventIDs of the NOEs that required an EOE and remove all columns but the ones listed below:
    neoeIDs = list(tabdf['EVENT-ID']) 
    searchdf = searchdf.loc[searchdf['NAME'].isin(neoeIDs)]
    searchdf = searchdf[['NAME', 'DATE_OF_EVENT', 'ASSOCIATED_EOE', 'ASSOCIATED_DNF', 'PRODUCT(S)_ASSOCIATED']]
    
    #this part is simply creating a dictionary of the NOE eventIDs and associated metadata so the dataframe of the table contains the correct orderings.
    #if a dictionary was not used the row values and column values would be arbitrary and incorrect.
    mydict = dict(zip(list(searchdf['NAME']), list(searchdf['ASSOCIATED_DNF'])))
    mydict1 = dict(zip(list(searchdf['NAME']), list(searchdf['ASSOCIATED_EOE'])))
    mydict2 = dict(zip(list(searchdf['NAME']), list(searchdf['DATE_OF_EVENT'])))
    mydict3 = dict(zip(list(searchdf['NAME']), list(searchdf['PRODUCT(S)_ASSOCIATED'])))
    tabdf.set_index('EVENT-ID', inplace = True)
    tabdf['ASSOCIATED_DNF'] = pd.Series(mydict)
    tabdf['ASSOCIATED_EOE'] = pd.Series(mydict1)
    tabdf['DATE_OF_EVENT'] = pd.Series(mydict2)
    tabdf['PRODUCT(S)_ASSOCIATED'] = pd.Series(mydict3)

    #next the EOE -> DNF escalation rate is found by dropping all rows without associated DNFs
    newdf = tabdf.dropna()
    dnfnum = len(newdf.index)
    myEmailMessage = myEmailMessage + "%s EOEs escalated to DNFs, making an EOE to DNF rate of %.2s percent. \n\n" % (dnfnum, math.floor((dnfnum / numeoe) * 100))
    pdf.write(5, "%s EOEs escalated to DNFs, making an EOE to DNF rate of %.2s percent. \n\n" % (dnfnum, math.floor((dnfnum / numeoe) * 100)))
    tabdf = tabdf[['Similarity', 'DATE_OF_EVENT', 'ASSOCIATED_DNF', 'ASSOCIATED_EOE', 'PRODUCT(S)_ASSOCIATED']]
    
    #this here are the conditionals for determining the severity of the NOE.
    #the current method is a very simple implementation and would be another top priority to overhaul.
    threatlevel = "Low"
    if (dnfnum != 0):
        threatlevel = "High"
    elif (eoetonoe >= 0.5):
        threatlevel = "Medium"
    
    myEmailMessage = myEmailMessage + "Risk level = %s.\n\n" % threatlevel
    pdf.write(5, "Risk level = %s.\n\n" % threatlevel)

    myTeamsMessage.title("%s Analyis Summary - %s Severity" % (eventid, threatlevel))

    
    #this is where the pdf is actually populated ... the encoding and decoding is just because the python pdf generation cannot handle different types of character types
    #this would be another area to improve
    for i in range(rowNumber):
        row = df.iloc[i]
        currentid = row['EVENTID'].encode('latin-1', 'replace').decode('latin-1')
        manager = row['NOE2_AREA_MANAGER'].encode('latin-1', 'replace').decode('latin-1')
        initiator = row['NOE2_NOE_INITIATOR'].encode('latin-1', 'replace').decode('latin-1')
        topic = row['NOE2_TOPIC'].encode('latin-1', 'replace').decode('latin-1')
        solution = row['NOE2_NOE_CORRECTIVE_ACTION']
        if solution is not None:
            solution = solution.encode('latin-1', 'replace').decode('latin-1')
        eoe = row['NOE2_EOE_REQUIRED']
        sim = row['Similarity']
        pdf.set_font("Times", style = 'B', size = 14)
        pdf.write(5, currentid + " (similiarity: %s)\n\n" % sim)

        pdf.set_font("Times", style = 'B', size=12)
        pdf.write(5, "Area Manager: ")
        pdf.set_font("Times", size=12)
        pdf.write(5, "%s\n" % manager)
        pdf.set_font("Times", style = 'B', size=12)
        pdf.write(5, "Initiator: ")
        pdf.set_font("Times", size=12)
        pdf.write(5, "%s\n" % initiator)
        pdf.set_font("Times", style = 'B', size=12)
        pdf.write(5, "EOE Required: ")
        pdf.set_font("Times", size=12)            
        pdf.write(5, "%s\n\n" % eoe)
        pdf.set_font("Times", style = 'B', size=12)
        pdf.write(5, "Description: ")
        pdf.set_font("Times", size=12)
        pdf.write(5, "%s\n\n" % topic)
        pdf.set_font("Times", style = 'B', size=12)
        pdf.write(5, "Solution: ")
        pdf.set_font("Times", size=12)
        pdf.write(5, "%s\n\n" % solution)
    pdf.output("%s_prereport.pdf" % eventid).encode('latin-1')
    
    return tabdf, myEmailMessage
   
def getScores(mylist): #meant to be used in conjunction with preppdf, retrieves eventIDs and similiarity values from NLP API.
    length = len(mylist)
    for i in range(length):
        mylist[i] = mylist[i].replace('"', "")
        mylist[i] = mylist[i].replace('(', "")
        mylist[i] = mylist[i].replace(')', "")
        mynewlist = [x for x in mylist if (len(x) == 22 or len(x) == 23) or len(x) == 24]
    myIDs = []
    myScores = []
    for x in mynewlist:
        myIDs.append((re.findall(re.escape("NOE") + '.{8}', x)[0]))
        myScores.append((re.findall(re.escape("Score") + '.{6}', x)[0]))

    for i in range(len(myIDs)):
        myIDs[i] = myIDs[i].replace(' ', "")

    for i in range(len(myScores)):
        myScores[i] = myScores[i].replace('Score: ', "")

    mydict = dict(zip(myIDs, myScores))
    return (mydict, myIDs)

def prepdf(mylist): #prepares dataframe consisting of eventIDs and similiarity values.
    myDict = getScores(mylist)[0]
    eventIDs = getScores(mylist)[1]
    conn = pymssql.connect(server="RHNALON15SQL03D", user="REGENERON\s.jack.lavelle", password=keyring.get_password("RHNSQL_s.jack", "s.jack.lavelle"), database="IOPS_Data_Warehouse")
    cursor = conn.cursor()
    query = """
    SELECT [EVENTID]
    ,[NOE2_AREA_MANAGER]
    ,[NOE2_NOE_INITIATOR]
    ,[NOE2_TOPIC]
    ,[NOE2_NOE_CORRECTIVE_ACTION]
    ,[NOE2_EOE_REQUIRED]
    FROM [IOPS_Data_Warehouse].[QProcess].[NOE_PAI_TBL]
    """
    
    results = cursor.execute(query)
    df = pd.read_sql_query(query, conn)
    conn.close()
    mydf = df.loc[df['EVENTID'].isin(eventIDs)]
    mydf['Similarity'] = None

    for nid, score in myDict.items():
        mydf.loc[(mydf['EVENTID'] == nid),'Similarity'] = score

    mydf = mydf.sort_values('Similarity', ascending = False)

    return mydf 

def processNOE(eventid, desc):
    #Firstly, description of the NOE is fed into the NLP API ... returning JSON that contains a fixed number of NOEs and their event descriptions.
    NLPurl = "http://dps-dss-176-074.itcorp.aws.regeneron.com:11000/public/api/v1/iops_sim/iops_sem_v1/run" #Information for API that interfaces with NLP model.
    NLPquery = {"query" : desc}
    NLPheaders = {
      'Authorization': 'Basic Zll4b3pPSUNsc29oRWVTZmE3aGszOUVvaUdKV2FoQVU6',
      'Content-Type': 'application/json'
    }
    #Three things: 1) an improvement of this project would be improving the Natural Language Processing (even better to use other Machine Learning techniques on other metadata of the NOE),
    #and 2) returning only a fixed number of NOEs is not the best ... instead the number of returned NOEs should be inherent to how many similiar NOEs are returned,
    #and 3) with the way I've approached this the JSON should really return only the eventids (the event descriptions can be easily attained).
    
    print("Processing %s." % eventid)
    print("Making call to NLP API.")
    payload = json.dumps(NLPquery)
    NLPresponse = requests.request("POST", NLPurl, headers = NLPheaders, data = payload).text
    print("Getting information from relevant NOEs.")
    mylist = re.findall(re.escape('(NOE') + '.{24}', NLPresponse)
    print("Compiling and preparing pdf document.")

    #Next the prepdf function is fed a list of eventIDs and prepares a dataframe of relevant metadata for each NOE.
    predf = prepdf(mylist) 

    #Next the message that will be sent into the Teams feed is initiated ... if I had more time I would clean this part up and turn it into its own function.

    myTeamsMessage = pymsteams.connectorcard("https://regn.webhook.office.com/webhookb2/827fed18-e919-4495-86dc-2295d3a8d89d@3e9aadf8-6a16-490f-8dcd-c68860caae0b/IncomingWebhook/fee07baac451478cae3a2b042e369d21/375a2df4-8e7c-4c6a-967c-2fca6768aa73")
    
    #Next we reach the bread and butter of the program ... the toPDF function. This returns two things 1) mydf - which is the actual dataframe that is printed, and 2) the email message is
    #event topic of the NOE.
    toPDFreturned = toPDF(eventid, predf, myTeamsMessage)
    mydf = toPDFreturned[0]
    myEmailMessage = toPDFreturned[1]

    #Next we move to generating the table pdf which we append first to the report.
    #genTable() returns a dataframe that is then converted to a string and sent into Teams.
    gendf = genTable(mydf, eventid)
    gendf = gendf.drop('Similarity', 1)
    sgendf = gendf.to_markdown(tablefmt="grid")

    #formatting the Teams message.
    mytopic = predf.loc[predf['EVENTID'] == eventid]['NOE2_TOPIC'].values[0]
    myTeamsMessage.text(mytopic)
    myMessageSection2 = pymsteams.cardsection()
    myMessageSection2.text(sgendf)
    myTeamsMessage.addSection(myMessageSection2)
    myTeamsMessage.send()

    #path where the report will be saved.
    path = "C:\\Users\\s.jack.lavelle\\Desktop\\work\\AWS\\%s_REPORT.pdf" % eventid
    merger = PdfFileMerger() #merge both pdfs into one.
    merger.append("%s_table.pdf" % eventid)
    merger.append("%s_prereport.pdf" % eventid)
    merger.write(path)
    merger.close()
    print("Generated %s report successfully." % eventid)
    os.remove("%s_prereport.pdf" % eventid)
    os.remove("%s_table.pdf" % eventid)
    emailReport("jack.lavelle@regeneron.com", path, eventid, myEmailMessage)
    os.remove(path)

def genTable(mydf, eventid):
    #First, every associated DNF/EOE/etc is filled in
    for i in range(len(mydf.ASSOCIATED_DNF)):
      if mydf.ASSOCIATED_DNF.values[i] == None:
              mydf.ASSOCIATED_DNF.values[i] = "No associated DNF"

    for i in range(len(mydf.ASSOCIATED_EOE)):
      if mydf.ASSOCIATED_EOE.values[i] == None:
              mydf.ASSOCIATED_EOE.values[i] = "No associated EOE"

    for i in range(len(mydf['PRODUCT(S)_ASSOCIATED'])):
      if mydf['PRODUCT(S)_ASSOCIATED'][i] == None:
              mydf['PRODUCT(S)_ASSOCIATED'][i] = "No product(s) associated"
    
    #from dataframe generate table and save as pdf.
    #This part should also be overhauled as it is the reason why the table pdf is a different size.
    fig, ax = plt.subplots() 
    fig.patch.set_visible(False)
    ax.axis('off')
    tab = ax.table(cellText=mydf.values, rowLabels=mydf.index, rowColours = ['gainsboro'] * len(mydf.index), colColours=['gainsboro'] * len(mydf.columns), colLabels=mydf.columns, loc='center')
    plt.title("%s Analysis Report" % eventid)
    plt.rcParams["font.family"] = "Times New Roman"
    tab.auto_set_font_size(False)
    tab.set_fontsize(11)
    tab.auto_set_column_width(col=list(range(len(mydf.columns))))
    plt.savefig("%s_table.pdf" % eventid, bbox_inches = "tight")

    return mydf

def emailReport(target, path, eventid, myEmailMessage):
    # Replace sender@example.com with your "From" address.
    # This address must be verified.
    SENDER = 'jacklavelle17@gmail.com'  
    SENDERNAME = 'Jack LaVelle'
    # Replace recipient@example.com with a "To" address. If your account.
    # is still in the sandbox, this address must be verified.
    RECIPIENT  = target

    # Replace smtp_username with your Amazon SES SMTP user name.
    USERNAME_SMTP = "AKIAQLOW5RJTKDGZ2JBK"

    # Replace smtp_password with your Amazon SES SMTP password.
    PASSWORD_SMTP = "BDRY4BYwH0y4/bLMzt0VGwBLxzhMH1qBVLxl3lI8Sou1"

    # (Optional) the name of a configuration set to use for this message.
    # If you comment out this line, you also need to remove or comment out
    # the "X-SES-CONFIGURATION-SET:" header below.
    #CONFIGURATION_SET = "ConfigSet"

    # If you're using Amazon SES in an AWS Region other than US West (Oregon), 
    # replace email-smtp.us-west-2.amazonaws.com with the Amazon SES SMTP  
    # endpoint in the appropriate region.
    HOST = "email-smtp.us-east-2.amazonaws.com"
    PORT = 587

    # The subject line of the email.
    SUBJECT = '%s Analysis Report' % eventid

    # The email body for recipients with non-HTML email clients.
    BODY_TEXT = ("Attached is the report for %s.\r\n" % eventid)

    # The HTML body of the email.
    BODY_HTML = """<html>
    <head></head>
    <body>
    <p>REALTIME NOE ANALYSIS SOLUTION AND REPORT. \n%s</p>
    </body>
    </html>
                """ % myEmailMessage

    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = SUBJECT
    msg['From'] = email.utils.formataddr((SENDERNAME, SENDER))
    msg['To'] = RECIPIENT

    part = MIMEApplication(open(path, 'rb').read())
    part.add_header('Content-Disposition', 'attachment', filename="%s_REPORT.pdf" % eventid)
    msg.attach(part)
    # Comment or delete the next line if you are not using a configuration set
    #msg.add_header('X-SES-CONFIGURATION-SET',CONFIGURATION_SET)

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(BODY_TEXT, 'plain')
    part2 = MIMEText(BODY_HTML, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    msg.attach(part)
    msg.attach(part2)

    # Try to send the message.
    try:  
        server = smtplib.SMTP(HOST, PORT)
        server.ehlo()
        server.starttls()
        #stmplib docs recommend calling ehlo() before & after starttls()
        server.ehlo()
        server.login(USERNAME_SMTP, PASSWORD_SMTP)
        server.sendmail(SENDER, RECIPIENT, msg.as_string())
        server.close()

    # Display an error message if something goes wrong.
    except Exception as e:
        print ("Error: ", e)
    else:
        print ("Email sent!\n") 

def monitor():
    #The start of my program ... this is where I continously poll the change data capture database ... looking for new NOE databases. (again this is not actually implemented on the real SQL database).
    #In the actual implementation, this python program would be converted into a Windows service to run continously through AlwaysUp.
    server = "regn-siera-dwh-sqlee1.cvmyu7sse9uu.us-east-1.rds.amazonaws.com"
    user = "REGENERON\jack.lavelle"
    password = keyring.get_password("jack.lavelle", "jack.lavelle") #NEVER store your real password (for example people have bots continously scanning GitHub for people who put their password in text).
    database = "cdc"
    query = """
    SELECT TOP (1000) [__$start_lsn]
        ,[__$end_lsn]
        ,[__$seqval]
        ,[__$operation]
        ,[__$update_mask]
        ,[OBJECTID]
        ,[CUSTOMOBJECTID]
        ,[EVENTID]
        ,[NOE2_AREA_MANAGER]
        ,[NOE2_NOE_INITIATOR]
        ,[NOE2_TOPIC]
        ,[NOE2_EVENT_DESCRIPTION]
        ,[NOE2_NOE_CORRECTIVE_ACTION]
        ,[NOE2_EOE_REQUIRED]
        ,[__$command_id]
    FROM [cdc].[cdc].[dbo_Query_CT]
    """

    conn = pymssql.connect(server, user, password, database)
    cursor = conn.cursor()

    results = cursor.execute(query)

    #next I take the return SQL query and turn it into a pandas dataframe.
    df = pd.read_sql_query(query, conn)

    current_length = len(df.index) #get current length of dataframe ... once this length changes you know you have a new NOE.

    print("Monitoring for updates:")
    while(True):
        #wait 5 seconds before polling cdc (change data capture) SQL table again.
        time.sleep(5)
        results = cursor.execute(query) 
        df = pd.read_sql_query(query, conn)
        diff = abs(current_length - len(df.index))
        if(diff != 0): #If current_length is different than df.index -> new entry
            cdf = df.tail(diff)
            cdf = cdf.rename(columns = {'__$operation' : 'operation'}) #default column name of '__$operation' creates issues with python, rename.
            cdf = cdf[cdf['operation'] != 3] #filter out operation 3 (should also filter out other operations ... the various operations correspond to what the change detected by cdc was)
            
            print("\nFound %s update(s).\n" % len(cdf.index)) 
            for x in range(0, len(cdf.index)): #for every new NOE added/updated, get the eventid and event_description and process that NOE.
                eventid = cdf.iloc[x]['EVENTID']
                eventdesc = cdf.iloc[x]['NOE2_EVENT_DESCRIPTION']
                processNOE(eventid, eventdesc) #processNOE is the function that kickstarts processing the NOE (not exactly a creative name I know)
            current_length = len(df.index) #update current_length.
        else:
            print('No new updates.')
        current_length = len(df.index)

    conn.close() #this is unreachable since it is in a while true loop but is included for completion's sake(not the best practice really)

#the monitor() function would be run continuously as all other functions are directly or indirectly called from it.
#processNOE() can be used to manually run NOEs

processNOE('NOE16-08426', 'On 23Aug2016 in room 1209, while executing a CIP of R5 Media Xfer Line per SOP MA3706 (1.0) (Cleaning and Sanitization of the Media Preparation Module in PA7), a level transmitter data fault alarm on the Media CIP Skid (ECN 52688) held the procedure during the second Rinse Drain after Caustic Wash.    The level transmitter data fault alarm on the Media CIP Skid (ECN 52688) occurred during Rinse Drain Operation after Caustic Wash at 0800hrs. During this operation WFI is added to the system to rinse the caustic solution to drain. The low alarm arose due to the level transmitter, LT-01, reading a false "NULL" even though the amount of solution in the vessel was within the acceptable range which is greater than zero. The null reading occurred on LT-01 which is on the Human Machine Interface (HMI). Operators manually opened HV-03 and HV-04 to drain solution from the tank. This immediately cleared the "NULL" reading on LT-01. The alarm was acknowledged and the procedure was restarted. The CIP proceeded with no further issues, and was documented in LOG-03578 (7.0) ECN 52856 Media Prep Filter Skid Logbook on 23Aug2016.')