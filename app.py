#!/usr/bin/python3

import json
import math
import requests
import urllib.request
from urllib.parse import quote_plus, unquote
import bit
from requests.auth import HTTPBasicAuth
from bitcoin.signmessage import BitcoinMessage, VerifyMessage
import os
from flask import Flask, render_template, request, redirect
import sys
import hashlib
import sqlite3
#from flask import Bootstrap
import optparse
from twisted.internet import reactor, ssl
from flask_cors import CORS, cross_origin
from PIL import Image
from collections import defaultdict
from werkzeug.contrib.cache import SimpleCache
from apscheduler.schedulers.background import BackgroundScheduler



scheduler = BackgroundScheduler()

cache = SimpleCache()

conn = sqlite3.connect('pepevote.db')

c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS verified_messages
             (address text, asset text, hash text PRIMARY KEY, block text, signature text, image text)''')
c.execute('''CREATE TABLE IF NOT EXISTS votes
             (address text PRIMARY KEY, block text, votes text, signature text)''')
c.execute('''CREATE TABLE IF NOT EXISTS delegates
             (source text PRIMARY KEY, delegate text, signature text)''')

conn.commit()
conn.close()

app = Flask(__name__)
CORS(app)

# app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # for 4MB max-limit.

UPLOAD_FOLDER = os.path.basename('uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

bitcoin_rpc_url = "http://localhost:8332"
xcpd_url = "http://localhost:4000/api/"
pepe_url = "http://rarepepewallet.com/feed"

headers = {'content-type': 'application/json'}
auth = HTTPBasicAuth('rpc', 'rpc')

burn_addy = "1BurnPepexxxxxxxxxxxxxxxxxxxAK33R"
my_addy   = "18E6DSBnrWkzkzMTMSkSnAjvVKNsRvardo"

home_dir = os.path.expanduser("~")

sslContext = ssl.DefaultOpenSSLContextFactory(
    os.path.join(home_dir, '.ssl/privkey.pem'),
    os.path.join(home_dir, '.ssl/cacert.pem'),
)
__port = 701


def getPort(value):
    return (__port, value)[value > 0]


def tornado(option, opt_str, value, parser):
    print('Tornado on port {port}...'.format(port=getPort(value)))
    from tornado.wsgi import WSGIContainer
    from tornado.httpserver import HTTPServer
    from tornado.ioloop import IOLoop

    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(getPort(value))
    IOLoop.instance().start()


def twisted(option, opt_str, value, parser):
    print('Twisted on port {port}...'.format(port=getPort(value)))
    from twisted.web.server import Site
    from twisted.web.wsgi import WSGIResource
    from twisted.python import log
    log.startLogging(sys.stdout)

    resource = WSGIResource(reactor, reactor.getThreadPool(), app)
    site = Site(resource)

    reactor.listenSSL(getPort(443), site,  sslContext)
    reactor.listenTCP(getPort(value), site, interface="0.0.0.0")
    reactor.run()


def builtin(option, opt_str, value, parser):
    print('Built-in development server on port {port}...'.format(port=getPort(value)))
    app.run(host="0.0.0.0",port=getPort(value),debug=True)


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def get_masterlist():
    global masterlist
    test = urllib.request.urlopen(pepe_url)
    masterlist = json.loads(test.read().decode())


def get_balances(address):
    payload = {
               "method": "get_balances",
               "params": {
                          "filters": [{"field": "address", "op": "==", "value": address},
                                     ],
                         },
               "jsonrpc": "2.0",
               "id": 0
              }

    response = requests.post(xcpd_url, data=json.dumps(payload), headers=headers, auth=auth)
    response_s = json.loads(response.text)
    assets = response_s['result']

    balances = {}

    for asset in assets:

        balances[asset['asset']] =  asset['quantity']

    return balances


def get_votes_cards(delegated_list):

    votes = 0

    for _address in delegated_list:
        balances = get_balances(_address)
        if len(balances) == 0:
            continue

        # Tally up votes for indivisibles
        if len(balances) < len(indivisibles):
            for asset in indivisibles:
                if asset in balances:
                    # Address has a Pepe asset, give proportional votes

                    card_votes = float(balances[asset])/float(indivisibles[asset]['quantity'])*1000
                    votes += math.floor(card_votes)

        else:
            for asset in balances:
                if asset in indivisibles:
                    # Address has a Pepe asset, give proportional votes

                    card_votes = float(balances[asset])/float(indivisibles[asset]['quantity'])*1000
                    votes += math.floor(card_votes)

        # Tally up votes for divisibles
        for asset in divisibles:
            if asset in balances:
                card_votes = float(balances[asset])/float(divisibles[asset]['quantity']*100000000)*1000
                votes += math.floor(card_votes)

    return votes


def get_votes_cash(delegated_list):
    # Approximately one million votes total
    votes = 0

    for _address in delegated_list:
        balances = get_balances(_address)

        if len(balances) == 0:
            continue

        try:
            pepecash = balances['PEPECASH']
        except:
            continue
        votes += math.floor((float(pepecash)/(700000000*100000000))*1000000)

    return votes


def get_candidates(start, end):
    payload = {
               "method": "get_sends",
               "params": {
                          "filters": [{"field": "destination" , "op": "==", "value": burn_addy},
                                      {"field": "asset"   , "op": "==", "value": "PEPECASH"},
                                      {"field": "quantity", "op": ">=" , "value": "300"}
                                      ],
                          "start_block": start,
                          "end_block": end
                         },
               "jsonrpc": "2.0",
               "id": 0
              }

    response = requests.post(xcpd_url, data=json.dumps(payload), headers=headers, auth=auth)
    response_s = json.loads(response.text)

    transactions = response_s['result']
    list = []
    for transaction in transactions:
        memo_hex = transaction['memo_hex']
        if not memo_hex == None:
            list.append(transaction['memo_hex'])

    return list


def split_masterlist():
    global divisibles, indivisibles

    divisibles   = {}
    indivisibles = {}

    for asset in masterlist:
        if masterlist[asset]['divisible'] == True:
            divisibles[asset] = masterlist[asset]
        else:
            indivisibles[asset] = masterlist[asset]

    # Remove Pepecash (used for other voting method)
    del divisibles['PEPECASH']


def setup():
    get_masterlist()
    split_masterlist()


def get_sends():
    payload = {
           "method": "get_sends",
           "params": {
                     },
           "jsonrpc": "2.0",
           "id": 0
          }

    response = requests.post(xcpd_url, data=json.dumps(payload), headers=headers, auth=auth)
    response_s = json.loads(response.text)
    #print(response_s)
    #print(response_s['result'])


def owns_asset(address, asset):
    assets = get_balances(address)
    if asset in assets:
        return True
    else:
        return False


def asset_issuance(asset):
    payload = {
       "method": "get_supply",
       "params": {
                  "asset": asset
                 },
       "jsonrpc": "2.0",
       "id": 0
      }

    response = requests.post(xcpd_url, data=json.dumps(payload), headers=headers, auth=auth)
    response_s = json.loads(response.text)
    issuance = response_s['result']
    return issuance


def get_submissions_data():

    dir = os.path.join('static', 'submitted')
    submissions = os.listdir(dir)

    scores = {}
    files = []
    hashes = []

    conn = sqlite3.connect('pepevote.db')
    c = conn.cursor()

    for submission in submissions:
        hash = sha256_checksum(os.path.join(dir,submission))
        if hash in hashes:
            continue
        hashes.append(hash)
        c.execute('SELECT * FROM verified_messages WHERE hash=?', (hash,))
        data = c.fetchone() # Hash is a unique constraint, will never be multiple
        if data is not None:
            (_, asset, _, _, _, _) = data
            scores[asset] = {}
            scores[asset]['cash_score'] = 0
            scores[asset]['card_score'] = 0
            files.append((os.path.join(dir, submission), asset, hash))

    conn.close()
    return (files, scores)


def get_current_block():
    payload = {
       "method": "get_running_info",
       "params": {
                     },
       "jsonrpc": "2.0",
       "id": 0
      }

    response = requests.post(xcpd_url, data=json.dumps(payload), headers=headers, auth=auth)
    response_s = json.loads(response.text)
    block = response_s['result']['bitcoin_block_count']
    return block


def update_scores():
    print("Updating scores")
    candidates = []

    (files, scores) = get_submissions_data()

    conn = sqlite3.connect('pepevote.db')
    c = conn.cursor()

    c.execute('SELECT * from votes')
    votes = c.fetchall()

    c.execute('SELECT * from delegates')
    delegates = c.fetchall()

    conn.close()

    # Get every delegate, and set them up in a dictionary
    delegate_mapping = defaultdict(list)    # mapping from delegates to an array of addresses delegated to them
    delegated_mapping   = {} # mapping from delegated addresses to the address they are delegated to

    for (delegated, delegate, _) in delegates: 
        delegate_mapping[delegate].append(delegated)
        delegated_mapping[delegated] = delegate

    for vote in votes:
        (address, _, set, _) = vote
        set = set.replace("'",'"')

        if address in delegated_mapping:
            if delegated_mapping[address] != "":
                # This address has been delegated, don't count its votes
                continue

        delegate_mapping[address].append(address)
        cash_votes = get_votes_cash(delegate_mapping[address])
        card_votes = get_votes_cards(delegate_mapping[address])

        user_votes = json.loads(set)
        for user_vote in user_votes:
            cash_score = (cash_votes * (int(user_vote['weight'])))/100
            card_score = (card_votes * (int(user_vote['weight'])))/100

            scores[user_vote['asset']]['cash_score'] += cash_score
            scores[user_vote['asset']]['card_score'] += card_score


    for file in files:
        (dir, asset, hash) = file
        issuance = asset_issuance(asset)
        thing = (asset, hash, dir, issuance, scores[asset]['card_score'], scores[asset]['cash_score'])
        candidates.append(thing)

    cache.set('candidates', candidates, timeout=300)
    return candidates


def insert_into_delegates(source, delegate, signature):
    tuple = (source, delegate, signature)
    conn = sqlite3.connect('pepevote.db')
    c = conn.cursor()

    c.execute("INSERT OR REPLACE INTO delegates(source, delegate, signature) VALUES(?,?,?)", tuple)
    conn.commit()
    conn.close()


def insert_into_verified_messages(address, asset, hash, block, signature, image):
    conn = sqlite3.connect('pepevote.db')
    c = conn.cursor()

    tuple = (address, asset, hash, block, signature, location)
    c.execute("INSERT INTO verified_messages(address, asset, hash, block, signature, image) VALUES(?, ?, ?, ?, ?, ?)", tuple)
    conn.commit()
    conn.close()


def get_existing_vote(address):
    conn = sqlite3.connect('pepevote.db')
    c = conn.cursor()

    # Check if this is a duplicate entry
    c.execute('SELECT * FROM votes WHERE address=?', (address,))
    entry = c.fetchone()
    conn.close()
    return entry


def get_existing_verified_message(hash, asset):
    conn = sqlite3.connect('pepevote.db')
    c = conn.cursor()

    # Check if this is a duplicate entry
    c.execute('SELECT * FROM verified_messages WHERE hash=? OR asset=?', (hash,asset))
    entry = c.fetchone()
    conn.close()
    return entry

# get_votes_cards
# input: address
# output: integer number of votes based on card holdings (except PEPECASH)
#
# get balances for address
# check every balance against dict for valid rarepepes
# 1000 votes per card
# votes = (address card balance / total card issuance) X 1000
# return sum of votes for all rarepepe holdings

# get_votes_cash
# input: address
# output: integer number of votes based on PEPECASH holdings

# get_candidates
# input: two block heights, threshold (submission buy-in)
# output:

#get_votes_cards(my_addy)


#setup()

#print(divisibles)
#votes_cards = get_votes_cards(my_addy)
#print("Address " + my_addy + " has " + str(votes_cards) + " Card votes")

#votes_cash = get_votes_cash(my_addy)
#print("Address " + my_addy + " has " + str(votes_cash) + " Cash votes")

#get_candidates(515320,515990)

#get_sends()

#vote_data = '{"block":515368,"address":"18E6DSBnrWkzkzMTMSkSnAjvVKNsRvardo","votes":[{"hash":"7e497501a28bcf9a353ccadf6eb9216bf098ac32888fb542fb9bfe71d486761f","weight": 100}]}'
#vote_json = json.loads(vote_data)
#vote_address = vote_json['address']
#vote_signature = "IKSEdxcSYzbZA5k5kSCuePuARr2j98GgPggXPQaNNoxkB9fpu9z1lsh6BYXMnAQmcX04td5SZAnpetptdVW4Em4="
#print(vote_address)
#vote_data_t = BitcoinMessage(vote_data)

#print(VerifyMessage(vote_address, vote_data_t, vote_signature))


setup()


@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/ajaxtest')
def ajaxtest():
    return render_template('ajaxtest.html')


@app.route('/rpwverify')
def rpwverify():
    failure = json.dumps({'success':False, 'status': 'Something went wrong.'}), 200, {'ContentType':'application/json'}
    success = json.dumps({'success':True, 'status': 'Your vote has been cast.'}), 200, {'ContentType':'application/json'}

    print(request)
    try:
        address = request.args['address']
        signature = unquote(request.args['signature'])
        hash = request.args['msg']

        vote_string = cache.get(hash)
        print(vote_string)

        message_object = json.loads(vote_string)
        block     = message_object['block']
        votes     = message_object['votes']

        m = hashlib.sha256()
        m.update(bytes(vote_string, encoding='utf-8'))
        if m.hexdigest() != hash:
            print("Something is very wrong")
            print("Hash", hash, "hexdigest", m.hexdigest())
            return failure

        data = BitcoinMessage(hash)
        verified = VerifyMessage(address, data, signature)

        if not verified:
            print('Fail due to unverified message')
            return failure

        entry = get_existing_vote(address)

        if entry is not None:
            # Check block height to see if message is reused
            (_, old_block, _, _) = entry

            if block <= old_block:
                print('Fail due to block number')
                return failure

        conn = sqlite3.connect('pepevote.db')
        c = conn.cursor()
        tuple = (address, block, str(votes), signature)
        c.execute("INSERT OR REPLACE INTO votes(address, block, votes, signature) VALUES(?, ?, ?, ?)", tuple)
        conn.commit()
        conn.close()

        print('Vote submitted successfully.')

        update_scores()
        return success

    except:
        print('Some fail I havent identified')
        return failure


@app.route('/vote_list')
def vote_list():
    return render_template('vote_list.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    hash = 0
    if 'image' not in request.files:
        upload_error='No image uploaded.'
        return render_template('create_submission.html', upload_error=upload_error)

    file = request.files['image']
    f = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(f)

    im = Image.open(file)

    (width, height) = im.size
    filetype        = im.format

    if (width != 400):
        upload_error = 'Image needs to be 400 pixels wide'
        return render_template('create_submission.html', upload_error=upload_error)

    if (height != 560):
        upload_error = 'Image needs to be 560 pixels tall'
        return render_template('create_submission.html', upload_error=upload_error)

    if filetype != 'JPEG' and filetype != 'GIF' and filetype != 'PNG':
        upload_error='File must be a jpeg, png, or gif'
        return render_template('create_submission.html', upload_error=upload_error)

    hash = sha256_checksum(f)
    print("File written: " + f)
    return render_template('create_submission.html', hash=hash)


@app.route('/get_votes', methods=['GET'])
def get_votes():
    print(request.args['address'])

    address = [request.args['address']]

    votes_cards = get_votes_cards(address)
    votes_cash  = get_votes_cash(address)
    print(str(votes_cards) + " + " + str(votes_cash))

    return render_template('votes.html',
                           votes_cards=votes_cards,
                           votes_cash=votes_cash
                           )


@app.route('/get_submissions', methods=['GET'])
def get_submissions():
    if request.method == 'GET':

        candidates = cache.get('candidates')

        if candidates is None:
            print("Shouldn't be here")
            candidates = update_scores()

        return render_template('submissions.html', candidates=candidates)


@app.route('/create_submission', methods=['GET', 'POST'])
def create_submission():
    if request.method == "GET":
        return render_template('create_submission.html')

    address = ''
    asset = ''
    hash = ''
    if 'address' in request.form: address = request.form['address']
    if 'asset'   in request.form: asset   = request.form['asset']
    if 'hash'    in request.form: hash    = request.form['hash']

    m = hashlib.sha256()

    block = get_current_block()

    message = '{"block":"' + str(block) + '","address":"' + address + '","image_hash":"' + hash + '","asset":"' + asset + '"}'
    m.update(bytes(message, encoding='utf-8'))
    msghash = m.hexdigest()

    return render_template('create_submission.html', message=message, hash=hash, msghash=msghash)


@app.route('/create_message', methods=['POST'])
def create_message():

    address = ''
    asset = ''
    hash = ''
    if 'address' in request.form: address = request.form['address']
    if 'asset'   in request.form: asset   = request.form['asset']
    if 'hash'    in request.form: hash    = request.form['hash']

    block = get_current_block()

    message = '{"block":"' + str(block) + '","address":"' + address + '","image_hash":"' + hash + '","asset":"' + asset + '"}'

    return render_template('create_submission.html', message=message, hash=hash)


@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')


@app.route('/delegate_votes', methods=['GET','POST'])
def delegate_votes():
    if request.method == 'GET':
        status = ''
        return render_template('delegate_votes.html', status=status)

    delegate_string = ''
    if 'delegate_string' in request.form: delegate_string = request.form['delegate_string']
    m = hashlib.sha256()
    m.update(bytes(delegate_string, encoding='utf-8'))

    return render_template('delegate_submit.html', delegate_string=delegate_string, delegate_string_hash=m.hexdigest())


@app.route('/delegate_submit', methods=['GET', 'POST'])
def delegate_submit():
    if request.method == 'GET':
        return render_template('delegate_submit.html')

    delegate_string = ''
    signature       = ''

    if 'delegate_string' in request.form: delegate_string = request.form['delegate_string']
    if 'signature'       in request.form: signature       = request.form['signature']

    if signature == "":
        status = 'Signature is missing'
        return render_template('delegate_submit.html', status=status, delegate_string=delegate_string)

    try:
        delegate_string_object = json.loads(delegate_string)
    except:
        print("errored.")
        status='Delegate String is not properly formatted JSON'
        return render_template('delegate_submit.html', status=status, delegate_string=delegate_string)

    try:
        source   = delegate_string_object['source']
        delegate     = delegate_string_object['delegate']

    except:

        if not 'source' in delegate_string_object:
            status = 'Source field is missing.'

        if not 'delegate' in delegate_string_object:
            status = 'Delegate field is missing.'

        return render_template('delegate_submit.html', status=status, delegate_string=delegate_string)

    data = BitcoinMessage(delegate_string)
    m = hashlib.sha256()
    m.update(bytes(data, encoding='utf-8'))

    try:
        verified = VerifyMessage(source, m.hexdigest(), signature)
    except:
        verified = False

    if not verified:
        status = 'Verification failed.'
        return render_template('delegate_submit.html', status=status, delegate_string=delegate_string)

    insert_into_delegates(source, delegate, signature)

    print('Delegation processed successfully.')

    status = 'Delegation processed successfully.'
    return render_template('delegate_submit.html', status=status, delegate_string=delegate_string)


@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if request.method == 'GET':

        candidates = cache.get('candidates')
        block = get_current_block()

        if candidates is None:
            print("Shouldn't be here")
            candidates = update_scores()

        return render_template('vote.html', candidates=candidates, block_num=block)

    else:
        vote_string = '{}'
        if 'vote_string' in request.form:
            vote_string = request.form['vote_string']

        m = hashlib.sha256()
        m.update(bytes(vote_string, encoding='utf-8'))
        vote_string_hash = m.hexdigest()
        return render_template('submit_vote.html', vote_string=vote_string, vote_string_hash=vote_string_hash)


@app.route('/vote_rpw', methods=['GET', 'POST'])
def vote_rpw():
    if request.method == 'GET':

        candidates = cache.get('candidates')
        block = get_current_block()

        if candidates is None:
            print("Shouldn't be here")
            candidates = update_scores()

        return render_template('vote_rpw.html', candidates=candidates, block_num=block)

    else:

        vote_string = '{}'
        if 'vote_string' in request.form:
            vote_string = request.form['vote_string']

        m = hashlib.sha256()
        m.update(bytes(vote_string, encoding='utf-8'))
        vote_string_hash = m.hexdigest()
        cache.set(m.hexdigest(), vote_string, timeout=300)
        return render_template('submit_vote_rpw.html', vote_string=vote_string, vote_string_hash=vote_string_hash)


@app.route('/submit_overview', methods=['GET'])
def submit_overview():
    return render_template('submit_overview.html')


@app.route('/submit_vote', methods=['GET', 'POST'])
def submit_vote():
    if request.method == 'GET':
        print(request.form)
        candidates = cache.get('candidates')
        block = get_current_block()

        if candidates is None:
            print("Shouldn't be here")
            candidates = update_scores()

        return render_template('vote.html', candidates=candidates, block_num=block)

    else:
        signature   = ''
        vote_string = ''

        if 'signature' in request.form: signature = request.form['signature']
        if 'vote_string' in request.form: vote_string = request.form['vote_string']

        if vote_string == "":
            candidates = cache.get('candidates')
            block = get_current_block()

            if candidates is None:
                print("Shouldn't be here")
                candidates = update_scores()

            return render_template('vote.html', candidates=candidates, block_num=block)


        m = hashlib.sha256()
        m.update(bytes(vote_string, encoding='utf-8'))

        if  signature == "":
            status = 'Signature is missing.'
            return render_template('submit_vote.html', vote_string=vote_string, vote_string_hash=m.hexdigest(), status=status)

        else:
            # TODO: Change 'image hash' to 'hash' for terseness
            # TODO: Change status to error for readability?

            # First, check if all relevant fields have been provided to the signed message.
            # If you don't do this, things die with malformed input.

            try:
                message_object = json.loads(vote_string)
            except:
                print("errored.")
                status='Message is not properly formatted JSON'
                return render_template('submit_vote.html', vote_string=vote_string, vote_string_hash=m.hexdigest(), status=status) # Make this a redirect to vote?

            try:
                address   = message_object['address']
                block     = message_object['block']
                votes     = message_object['votes']

            except:

                if not 'address' in message_object:
                    status = 'Address field is missing.'

                if not 'votes' in message_object:
                    status = 'Votes field is missing.'

                if not 'block' in message_object:
                    status = 'Block field is missing.'

                return render_template('submit_vote.html', vote_string=vote_string, status=status) # redirect to vote

            data = BitcoinMessage(m.hexdigest())
            try:
                verified = VerifyMessage(address, data, signature)

            except:
                status = 'Verification failed - signature is malformed.'
                return render_template('submit_vote.html', status=status, vote_string=vote_string, vote_string_hash=m.hexdigest())

            if not verified:
                status = 'Verification failed.'
                return render_template('submit_vote.html', status=status, vote_string=vote_string, vote_string_hash=m.hexdigest())

            else:
                entry = get_existing_vote(address)

                if entry is not None:
                    # Check block height to see if message is reused
                    (_, old_block, _, _) = entry

                    if block <= old_block:
                        print("Reusing old message")
                        status = 'Error: reused old vote'
                        return render_template('submit_vote.html', status=status, vote_string=vote_string, vote_string_hash=m.hexdigest())

                conn = sqlite3.connect('pepevote.db')
                c = conn.cursor()

                tuple = (address, block, str(votes), signature)
                c.execute("INSERT OR REPLACE INTO votes(address, block, votes, signature) VALUES(?, ?, ?, ?)", tuple)
                conn.commit()
                conn.close()

                print('Vote submitted successfully')

                status = 'Vote submitted successfully.'
                update_scores()
                return render_template('submit_vote.html', vote_string=vote_string, status=status)


@app.route('/submit_vote_rpw', methods=['GET', 'POST'])
def submit_vote_rpw():
    if request.method == 'GET':
        return redirect('/vote_rpw')

    else:
        vote_string = ''

        if 'vote_string' in request.form: vote_string = request.form['vote_string']

        if vote_string == "":
            return redirect('/vote_rpw')

        m = hashlib.sha256()
        m.update(bytes(vote_string, encoding='utf-8'))
        cache.set(m.hexdigest(), vote_string, timeout=300)


@app.route('/submit_message', methods=['POST'])
def submit_message():
    message   = ''
    signature = ''

    if 'message'   in request.form: message   = request.form['message']
    if 'signature' in request.form: signature = request.form['signature']

    if message == "":
        registration_error = 'Message is missing'
        return render_template('create_submission.html', registration_error=registration_error)

    m = hashlib.sha256()
    m.update(bytes(message, encoding='utf-8'))

    if signature == "":
        registration_error = 'Signature is missing'
        return render_template('create_submission.html', registration_error=registration_error, msghash=m.hexdigest())

    else:

        try:
            message_object = json.loads(message)
        except:
            print("errored.")
            registration_error='Message is not properly formatted JSON'
            return render_template('create_submission.html', registration_error=registration_error, msghash=m.hexdigest())

        try:
            address = message_object['address']
            asset   = message_object['asset']
            hash    = message_object['image_hash']
            block   = message_object['block']

        except:

            if not 'address' in message_object:
                registration_error = 'Address field is missing.'

            if not 'asset' in message_object:
                registration_error = 'Asset field is missing.'

            if not 'image_hash' in message_object:
                registration_error = 'Hash field is missing.'
                return render_template('create_submission.html', registration_error=registration_error, message=message, msghash=m.hexdigest())

            if not 'block' in message_object:
                registration_error = 'Block field is missing.'

            return render_template('create_submission.html', registration_error=registration_error, hash=hash, message=message, msghash=m.hexdigest())

        data = BitcoinMessage(m.hexdigest())
 
        try: 
            verified = VerifyMessage(address, data, signature)
        except:
            verified = False

        if not verified:
            registration_error = 'Signature verification failed.'
            return render_template('create_submission.html', registration_error=registration_error,message=message,hash=hash, msghash=m.hexdigest())

        else:
            entry = get_existing_verified_message(hash,asset)

            if entry:
                registration_error = 'This asset or image has already been submitted this week.'
                return render_template('create_submission.html', registration_error=registration_error,hash=hash,message=message, msghash=m.hexdigest())

            else: # Entry is not a duplicate

                # Check if address actually owns the asset in question
                if not owns_asset(address, asset):
                    print(address)
                    print(asset)
                    registration_error = 'The provided address does not have the provided asset.'
                    return render_template('create_submission.html', registration_error=registration_error, hash=hash, message=message, msghash=m.hexdigest())

                # Check if the burn fee is paid
                paid = False

                candidates = get_candidates(532129,550000)

                for candidate in candidates:
                    if hash == candidate:
                        paid = True

                        # TODO: Check if anyone has ever used this hash before

                if not paid:
                    registration_error = 'Burn fee has not been paid.'
                    return render_template('create_submission.html', registration_error=registration_error,message=message,hash=hash, msghash=m.hexdigest())

                # TODO: Check if the asset is a duplicate of an existing one

                # Check if hash matches an uploaded image
                match = False

                dir = 'uploads'
                submissions = os.listdir(dir)

                candidates = []
                for submission in submissions:
                    if not submission == "temp":
                        candidates.append(os.path.join(dir, submission))

                for candidate in candidates:
                    candidate_hash = sha256_checksum(candidate)

                    print(candidate)
                    print(candidate_hash)

                    if hash == candidate_hash:
                        match = True
                        submission_path = candidate

                if not match:
                    registration_error = 'No uploaded image has the provided hash.'
                    return render_template('create_submission.html', registration_error=registration_error, hash=hash, message=message, msghash=m.hexdigest())

                location = os.path.join('static', 'submitted', submission_path[8:])
                os.rename(submission_path, location)

                conn = sqlite3.connect('pepevote.db')
                c = conn.cursor()

                tuple = (address, asset, hash, block, signature, location)
                c.execute("INSERT INTO verified_messages(address, asset, hash, block, signature, image) VALUES(?, ?, ?, ?, ?, ?)", tuple)
                conn.commit()
                conn.close()

                success = 'Verification succeeded, your art has been registered.'


    try:
        return render_template('create_submission.html', success=success,hash=hash,message=message, msghash=m.hexdigest())
    except:
        return render_template('create_submission.html')


def main():
    parser = optparse.OptionParser(usage="%prog [options]  or type %prog -h (--help)")
    parser.add_option('--tornado', help='Tornado non-blocking web server', action="callback", callback=tornado,type="int");
    parser.add_option('--twisted', help='Twisted event-driven web server', action="callback", callback=twisted, type="int");
    parser.add_option('--builtin', help='Built-in Flask web development server', action="callback", callback=builtin, type="int");
    job = scheduler.add_job(update_scores, 'interval', minutes=2)
    scheduler.start()
    update_scores()
    # update_scores runs twice sometimes on startup, that's ok. Not a huge deal.
    (options, args) = parser.parse_args()
    parser.print_help()

if __name__ == "__main__":
    main()
