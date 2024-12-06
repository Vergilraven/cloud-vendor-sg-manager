import sys
import csv
import json
import random
import asyncio
import requests

from pathlib import Path
from datetime import datetime as dt
from alibabacloud_ecs20140526.client import Client as Ecs20140526Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526 import models as ecs_20140526_models
from alibabacloud_tea_util import models as util_models


class GetLocalIpAddress:

    @staticmethod
    def get_external_ip() -> str:
        try:
            ip_addr_website = 'https://ip.me'
            ip_addr_resp = requests.get(url=ip_addr_website)
            if ip_addr_resp.status_code == 200:
                return ip_addr_resp.text
            else:
                raise Exception("==> GET ip address error <==")
        except Exception as e:
            raise e

class SecretKeeper:
    def __init__(self, secret_file: Path) -> None:
        self.secret_file = secret_file

    def get_secrets(self) -> dict:
        secrets_dic = dict()
        secrets_dic["ak"] = SecretKeeper.__access__(self.secret_file)
        secrets_dic["sk"] = SecretKeeper.__secret__(self.secret_file)
        secrets_dic["reg"] = SecretKeeper.__region__(self.secret_file)
        secrets_dic["sg_id"] = SecretKeeper.__sg_id__(self.secret_file)
        return secrets_dic

    @staticmethod
    def __access__(secure_file: Path) -> str:
        csv_file = open(secure_file)
        csv_res = csv.reader(csv_file)
        rows = [row for row in csv_res]
        aliyun_ak = rows[1][0]
        csv_file.close()
        return aliyun_ak

    @staticmethod
    def __secret__(secure_file: Path) -> str:
        csv_file = open(secure_file)
        csv_res = csv.reader(csv_file)
        rows = [row for row in csv_res]
        aliyun_sk = rows[1][1]
        csv_file.close()
        return aliyun_sk

    @staticmethod
    def __region__(secure_file: Path) -> str:
        csv_file = open(secure_file)
        csv_res = csv.reader(csv_file)
        rows = [row for row in csv_res]
        aliyun_reg = rows[1][2]
        csv_file.close()
        return aliyun_reg

    @staticmethod
    def __sg_id__(secure_file: Path) -> str:
        csv_file = open(secure_file)
        csv_res = csv.reader(csv_file)
        rows = [row for row in csv_res]
        aliyun_sg_id = rows[1][3]
        csv_file.close()
        return aliyun_sg_id

class EcsSgManager(SecretKeeper):
    def __init__(self, secret_file: Path) -> None:
        super().__init__(secret_file)

    @staticmethod
    def create_client(reg_name: str, ak_id: str, sk_id: str) -> Ecs20140526Client:
        config = open_api_models.Config(
            access_key_id=ak_id,
            access_key_secret=sk_id
        )
        config.endpoint = f'ecs.{reg_name}.aliyuncs.com'
        return Ecs20140526Client(config)

    @staticmethod
    def read_ip_lst(ip_file=Path("./ip-addresses.txt")) -> bool:
        with open(file=ip_file, mode="r") as ip_f:
            ip_lst = ip_f.readlines()
        return ip_lst

    @staticmethod
    def write_ip_lst(ip_addr: str, ip_file=Path("./ip-addresses.txt")) -> None:
        with open(file=ip_file, mode="a") as ip_f:
            ip_f.write(f"{ip_addr}\n")

    @staticmethod
    def check_state(state_code: int) -> bool:
        try:
            if state_code == 200:
                return True
            else:
                return False
        except KeyError:
            return False

    @staticmethod
    def is_in_sg_permissions(sg_api_data: dict, protocol_method: str) -> bool:
        port_range = sg_api_data.get("PortRange")
        match protocol_method:
            case "ssh":
                check_ssh_port = "22/22"
                if check_ssh_port == port_range:
                    return True
                else:
                    return False
            case "mysql":
                check_http_port = "3306/3306"
                if check_http_port == port_range:
                    return True
                else:
                    return False
            case "https":
                check_https_port = "443/443"
                if check_https_port == port_range:
                    return True
                else:
                    return False
            case _:
                return False

    @staticmethod
    def match_ip_addr(check_ip_addr: str, source_ip_addr: str) -> bool:
        if f"{check_ip_addr.replace('\n', '').rstrip('').lstrip('')}" == f"{source_ip_addr}":
            return True
        elif f"{check_ip_addr.replace('\n', '').rstrip('').lstrip('')}/32" == f"{source_ip_addr}":
            return True
        else:
            return False

    @staticmethod
    def sg_details_parser(sg_api_data: dict, check_ip_addr: str) -> None:
        try:
            sg_info = sg_api_data["Permissions"]["Permission"]
            call_back = list()
            for _, items in enumerate(sg_info):
                record_data = dict()
                create_time = items.get("CreateTime")
                source_ip_addr = str(items.get("SourceCidrIp")).replace("\n", "").rstrip("").lstrip("")
                port_range = items.get("PortRange")
                if EcsSgManager.match_ip_addr(check_ip_addr, source_ip_addr):
                    record_data["ipAddress"] = source_ip_addr
                    record_data["createTime"] = create_time
                    record_data["portRange"] = port_range
                    call_back.append(record_data)
            return call_back
        except KeyError as e:
            print("==> Parse API data error <==")

    async def get_sg_details_request(self, current_ip_addr: str) -> None:
        config = super().get_secrets()
        ak = config["ak"]
        sk = config["sk"]
        reg = config["reg"]
        sg_id = config["sg_id"]
        ecs_client = EcsSgManager.create_client(reg_name=reg, ak_id=ak, sk_id=sk)
        sg_resp = ecs_20140526_models.DescribeSecurityGroupAttributeRequest(region_id=reg,
                                                                            security_group_id=sg_id)
        runtime = util_models.RuntimeOptions()
        try:
            sg_details_resp = await ecs_client.describe_security_group_attribute_with_options_async(sg_resp, runtime)
            sg_details_body = sg_details_resp.body
            sg_details_head = sg_details_resp.headers
            sg_details_state_code = sg_details_resp.status_code
            if EcsSgManager.check_state(sg_details_state_code):
                sg_details_map = json.dumps(sg_details_body.to_map(), indent=4)
                sg_details_info = json.loads(sg_details_map)
                ip_check_res = EcsSgManager.sg_details_parser(sg_api_data=sg_details_info, check_ip_addr=current_ip_addr)
                if ip_check_res:
                    EcsSgManager.write_ip_lst(ip_addr=current_ip_addr)
                    print(ip_check_res)
                    print("==> record local ip address <==")
                else:
                    perm_dict = dict()
                    perm_dict["policy"] = "accept"
                    perm_dict["priority"] = random.choice(range(1, 101))
                    perm_dict["ip_protocol"] = "TCP"
                    perm_dict["source_cidr_ip"] = f"{current_ip_addr.replace('\n', '').rstrip('').lstrip('')}/32"
                    perm_dict["portRange"] = "22/22"
                    perm_dict["description"] = f"work-from-home-ip-{dt.now().strftime('%Y%m%d-%H%M%S')}"
                    await self.create_sg_inbound(permissions_dic=perm_dict)
                    print(perm_dict)
                    EcsSgManager.write_ip_lst(ip_addr=current_ip_addr)
                    print("==> Record ip address in security group <==")
            else:
                sg_details_headers = json.dumps(sg_details_head.to_map(), indent=4)
                sg_details_headers_info = json.loads(sg_details_headers)
                print(sg_details_headers_info)
                print("Error occurred")

        except Exception as err:
            raise err

    async def create_sg_inbound(self, permissions_dic: dict) -> None:
        config = super().get_secrets()
        ak = config["ak"]
        sk = config["sk"]
        reg = config["reg"]
        sg_id = config["sg_id"]
        add_permissions = ecs_20140526_models.AuthorizeSecurityGroupRequestPermissions(
            policy=permissions_dic["policy"],
            priority=permissions_dic["priority"],
            ip_protocol=permissions_dic["ip_protocol"],
            source_cidr_ip=permissions_dic["source_cidr_ip"],
            port_range=permissions_dic["portRange"],
            description=permissions_dic["description"]
        )
        ecs_client = EcsSgManager.create_client(reg_name=reg, ak_id=ak, sk_id=sk)
        sg_resp = ecs_20140526_models.AuthorizeSecurityGroupRequest(region_id=reg, security_group_id=sg_id,
                                                                     permissions=[add_permissions])

        runtime = util_models.RuntimeOptions()
        try:
            await ecs_client.authorize_security_group_with_options_async(sg_resp, runtime)
        except Exception as err:
            print(err)

    async def sg_runner(self) -> None:
        ip_lst = EcsSgManager.read_ip_lst()
        current_ip_addr = GetLocalIpAddress.get_external_ip()
        formated_current_ip = f"{current_ip_addr.replace('\n', '').rstrip('').lstrip('')}"
        if [x for x in ip_lst if x not in formated_current_ip]:
            print("==> IP found <==")
            sys.exit(0)
        else:
            print("==> Ip address not record in local laptop <==")
            await self.get_sg_details_request(current_ip_addr)

if __name__ == '__main__':
    sg_manager = EcsSgManager(Path("./configurations/account.csv"))
    asyncio.run(sg_manager.sg_runner())
