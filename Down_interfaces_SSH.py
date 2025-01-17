import paramiko
import re
import requests
import json
import sys

XTOKEN = sys.argv[1]
PROTOCOL = "http://"
RVISION = sys.argv[2]
incident = sys.argv[3]


def text_table_to_list(text : str, columns_qty : int, header:bool=True):
    text = re.sub(" + ", " ", text)
    text = text.split("\n")
    res = []
    for i, value in enumerate(text):
        if header:
            if i == 0:
                continue
        if value == "":
            break
        value = value.strip()
        value_list = value.split(" ")
        if len(value_list) > columns_qty:
            temp = value_list[columns_qty - 1:]
            temp = ' '.join(temp)
            del value_list[columns_qty - 1:]
            value_list.append(temp)
        res.append(value_list)
    return res


class SSH_connection():
    def __init__(self, hostname, username, password, port) -> None:
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port


    def connect(self):
        self.ssh_client.connect(
            hostname=self.hostname,
            username=self.username,
            password=self.password,
            port=self.port)

    def close(self):
        self.ssh_client.close()

    def pass_command(self, command: str, sudo=False):
        print(command)
        stdin, stdout, stderr = self.ssh_client.exec_command(command, get_pty=sudo)
        return stdin, stdout, stderr


    def shutdown_all_network_interfaces(self):
        """Turns off working network interfaces."""
        self.pass_command(command='sudo /usr/bin/nmcli networking off', sudo=False)



    def get_info(self, protocol: str, rvision: str, XToken: str, incident: str) -> list:
        requests.packages.urllib3.disable_warnings()
        s = requests.Session()
        incidents = s.get(
            protocol + rvision + '/api/v2/incidents' + '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"'+incident+'\"}]',
            headers={'X-Token': XToken},
            verify=False)
        incidentsResult = incidents.json()
        return incidentsResult['data']['result'][0]['ip_address_ssh']


if __name__ == '__main__':
    # Параметры SSH

    # Прод
    # host = api.inc_json['data']['result'][0]['ip_address']
    # user = ???
    # passw = ???
    # port = 22

    # Стенд
    host = SSH_connection.get_info(self = SSH_connection, protocol=PROTOCOL, rvision=RVISION, XToken = XTOKEN, incident= incident)
    port = 22
    # SSH пользователь
    user = sys.argv[4]
    passw = sys.argv[5]

    # Подключение SSH
    client = SSH_connection(host, user, passw, port)
    client.connect()
    client.shutdown_all_network_interfaces()
    client.close()
