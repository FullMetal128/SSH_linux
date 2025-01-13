import paramiko
import re
import logging
import requests
import json


ip_rvision = '10.22.20.140'
XTOKEN = '78479506a4173b34305b9168ea15b71a839cadca3698dc70185f3c742f58032d'
PROTOCOL = "http://"
FILTER = '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"{{tag.IDENTIFIER}}\"}]' # заменить 24-01-1 на тэг, на релизе добавить фильтр в ф-ю get_info
RVISION = '10.22.20.140'

#-----------------------LOGGING/
class ColoredFormatter(logging.Formatter):
    COLORS = {'DEBUG': '\033[96m', 'INFO': '\033[95m', 'WARNING': '\033[93m',
              'ERROR': '\033[91m', 'CRITICAL': '\033[95m'}
    def format(self, record):
        log_fmt = f"%(asctime)s ->>  {self.COLORS.get(record.levelname, '')} %(message)s\033[0m"
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', handlers=[logging.StreamHandler()])
logging.getLogger().handlers[0].setFormatter(ColoredFormatter())
logging.info('script for ASA - RV SOAR')
#-----------------------LOGGING\

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

    def shutdown_network_interfaces(self, ifname: str):
        """Turns off working network interfaces."""
        self.pass_command(command=f'sudo ip link set {ifname} down', sudo=False)

    def shutdown_all_network_interfaces(self):
        """Turns off working network interfaces."""
        self.pass_command(command='sudo /usr/bin/nmcli networking off', sudo=False)



    def get_info(self, protocol: str, rvision: str, XToken: str, incident: str) -> list:
        requests.packages.urllib3.disable_warnings()
        s = requests.Session()
        # фильтр в инцидентах заменить
        incidents = s.get(
            protocol + rvision + '/api/v2/incidents' + '?filter=[{\"property\":\"identifier\",\"operator\":\"=\",\"value\":\"24-10-11\"}]',
            headers={'X-Token': XToken},
            verify=False)
        incidentsResult = incidents.json()
        return incidentsResult

    def update(self):
        # получение списка IP
        DATA_EXPORT = self.get_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident='24-10-11')['data']['result'][0]['if_list_ssh']
        logging.info(DATA_EXPORT)
        DATA_IMPORT = DATA_EXPORT
        DATA_IMPORT = self.sh_if()
        logging.info(DATA_IMPORT)

        data = {'identifier': '24-10-11', 'if_list_ssh': DATA_IMPORT}  # заменить потом на тэг
        requests.post(PROTOCOL + RVISION + '/api/v2/incidents', headers={'X-Token': XTOKEN}, data=json.dumps(data),
                      verify=False)

    def update_pr(self):
        DATA_EXPORT = self.get_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident='24-10-11')['data']['result'][0]['processes_list_ssh']
        self.get_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident='24-10-11')['data']['result'][0]['processes_list_ssh']
        logging.info(DATA_EXPORT)
        DATA_IMPORT = DATA_EXPORT
        DATA_IMPORT = self.processes_list()
        logging.info(DATA_IMPORT)

        data = {'identifier': '24-10-11', 'processes_list_ssh': [{}]}  # заменить потом на тэг
        requests.post(PROTOCOL + RVISION + '/api/v2/incidents', headers={'X-Token': XTOKEN}, data=json.dumps(data),
                      verify=False)

    def sh_if(self): #для отправки интерфейсов в R-V
        names = []
        _, out, _ = self.pass_command(f'ip -br link show')
        interfaces = text_table_to_list(out.read().decode(), 10)
        for i in interfaces:
            names.append({'interface': i[0]})
        return names

    def processes_list(self):
        process = []
        _, out, _ = self.pass_command(f'ps -e -o uid,pid,ppid,c,sz,time,cmd')
        pr = text_table_to_list(out.read().decode(), 8)
        for i in pr:
            process.append({"UID": i[0], "PID": i[1], "PPID": i[2], "CC": i[3], "SZ": i[4], "TIME": i[5], "CMD": i[6], "to_kill": False})
        return process



if __name__ == '__main__':
    # Параметры SSH

    # Прод
    # host = api.inc_json['data']['result'][0]['ip_address']
    # user = ???
    # passw = ???
    # port = 22

    # Стенд
    host = '10.22.71.120'
    port = 22
    # SSH пользователь
    user = 'guest'
    passw = 'P@$$w0rD'

    # Подключение SSH
    client = SSH_connection(host, user, passw, port)
    client.connect()
    print(client.sh_if())
    print(client.get_info(protocol=PROTOCOL, rvision=RVISION, XToken=XTOKEN, incident='24-10-11'))
    print(client.processes_list())
    client.update_pr()
    #client.update()
    #client.shutdown_network_interfaces("ens33")
    #client.up_network_interfaces('ens33')
    #client.shutdown_all_network_interfaces()
    client.close()
