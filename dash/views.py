from django.shortcuts import render
import time,os,json
from django.http import JsonResponse
import nmap
from nmap import PortScanner

def scan_view(request, ip_address):
    result = perform_scan(ip_address)
    return JsonResponse(result, safe=False)

def perform_scan(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-sV ')
    return nm.all_hosts(), nm[ip_address]

def execute_command(request):
    # Execute puredns command and save output to file
    os.environ["PATH"] += ":/home/kali/go/bin"
    
    # Execute puredns command and save output to fill

    params = request.POST
    user=str(params.get('user'))
    concur = str(params.get("concurrency"))
    optd = str(params.get("optd"))
    timeout = str(params.get("timeout"))
    portd = str(params.get("portd"))
    method = str(params.get("method")).upper
    url_fetch = str(params.get("url"))
    opts=str(params.get('opts'))
    ports=str(params.get('ports'))
    batch_size=str(params.get('batch_size'))
    ran=str(params.get('range'))
    ulimit=str(params.get('ulimit'))

    os.popen('touch ./'+user+'/urls.txt')
    url_fetch_path='./'+user+'/urls.txt'
    url_output_path = './'+user+'/pure_output.txt'
    with open(url_fetch_path,'w') as file:
        file.write(url_fetch)

    puredns_command = "puredns resolve --resolvers /home/kali/go/bin/resolvers.txt "+url_fetch_path+" > "+url_output_path
    os.system(puredns_command)
    print("Puredns tool executed")

    # Get the current timestamp in milliseconds
    timestamp = str(time.time() * 1000)

    p=os.popen('find . -name '+user)
    if str(p.read())=='':
        os.popen('mkdir '+user)
    os.popen('mkdir ./'+user+'/'+timestamp)

    if url_fetch=='':
        raise Exception('Please provide host address or name.')
    cmd='rustscan --ulimit '+ulimit+' -ga '+url_fetch

    if opts.__contains__('p'):
        if ports=='':
            ports='80,443,7643'
        cmd+=' -p '+ports
        
    elif opts.__contains__('r'):
        if ran=='':
            ran='0-4095'
        cmd+=' -r '+ran

    if opts.__contains__('b'):
        if batch_size=='':
            batch_size=4096
        cmd+=' -b '+batch_size    
        
    o=os.popen(cmd)
    ostr=o.read().split('\n')
    res=gen_Jres(ostr)

    json_format = " | awk '!x[$0]++' | jq -R '.' | jq -s '{ \"protocols\": . }'"
    command = "cat "+url_output_path+" | httprobe"
    # Prepare commands for processing the output file
    if optd.__contains__('p'):
        command += ' -prefer-https'
    elif optd.__contains__('x'):
        command += ' -p '+portd
    elif optd.__contains__('c'):
        command = command + ' -c '+concur
    elif optd.__contains__('t'):
        command = command + ' -t '+timeout
    elif optd.__contains__('s'):
        command += ' -s'
    elif optd.__contains__('m'):
        command = command + ' -method '+method
    command += json_format
    output = os.popen(command).read().strip()

    # Convert the output to a JSON object
    json_output = json.loads(output)
    print("Httprobe tool executed")

    merged_json = {**res, **json_output}

    os.popen('touch ./'+user+'/'+timestamp+'/output.json')
    fpath='./'+user+'/'+timestamp+'/output.json'
    with open(fpath,'w') as file:
        json.dump(merged_json,file)

    # Return the JSON response
    return JsonResponse(merged_json)

def gen_Jres(ostr):
    #Function generate dictionary object in JSON format
    res={}
    for s in ostr:
    
        if s=='':
            continue

        ip=s.split(' ')[0]
        ports=set()
        temp=s.split(' ')[-1].split('-> [')[-1].split(']')[0].split('[')[-1]

        for p in temp.split(','):
            ports.add(p)
        res.update({ip:list(ports)})
    
    return res