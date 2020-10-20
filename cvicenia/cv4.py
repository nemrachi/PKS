import socket
import http.client
import requests
import json

url = "https://pieskovisko.netw.sk/zabbix/api_jsonrpc.php"

def api_authenticate(uname, upass):
    payload = '{\n' \
    '\"jsonrpc\": \"2.0\",\n' \
    '\"method\": \"user.login\",\n' \
    '\"params\": {\n' \
    '\"user\": \"' + uname + '\",\n' \
    '\"password\": \"' + upass + '\"\n' \
    '},\n' \
    '\"id\": 1,\n' \
    '\"auth\": null\n' \
    '}' \

    headers = {
    'Content-Type': "application/json",
    'cache-control': "no-cache",
    'Postman-Token': "00f3a559-670e-449d-b0d1-312ca6e1349d"
    }

    response = requests.request("POST", url, data=payload, headers=headers)

    login_response = json.loads(response.text)
    auth = login_response["result"]
    return auth


def api_getvalue(authcode, key):
    payload = '{\n \"jsonrpc\": \"2.0\",\n \"method\":' \
    '\"item.get\",\n \"params\": {\n \"output\": \"extend\",\n' \
    '\"hostids\": \"10263\",\n \"search\": {\n \"key_\":' \
    '\"' + key + '\"\n },\n \"sortfield\": \"name\"\n' \
    '},\n \"auth\": \"' + authcode + '\",\n \"id\":' \
    '1\n}' \

    headers = {
    'Content-Type': "application/json",
    'cache-control': "no-cache",
    'Postman-Token': "00f3a559-670e-449d-b0d1-312ca6e1349d"
    }

    response = requests.request("POST", url, data=payload, headers=headers)

    apidata = json.loads(response.text);
    apivalue = apidata["result"][0]["lastvalue"]
    return apivalue

authcode = api_authenticate("student","student")

temp_ba = api_getvalue(authcode,"api_weather")
temp_ba_celsius = float(temp_ba) - 273.15
print("Aktualna teplota v Bratislave: {} C".format(round(temp_ba_celsius,2)))

fuel_price = api_getvalue(authcode,"http_slovnaft")
print("Cena Natural95 na Slovnaft, Botanicka: {} Eur / liter".format(fuel_price))

nix_data = api_getvalue(authcode,"html_parsed_nix")
print("Aktualny datovy tok cez uzol NIX.sk: {} Gb/s".format(round(float(nix_data),2)))
