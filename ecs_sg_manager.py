import sys
import os
from pathlib import Path

ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

from utils.loggie import logger

import csv
import json
import yaml
import random
import asyncio
import requests

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

    @staticmethod
    def file_extension(file_path: str | Path) -> str:
        path = Path(file_path)
        return path.suffix.lstrip('.')

    def get_secrets(self) -> dict:
        secrets_dic = dict()
        if SecretKeeper.file_extension(self.secret_file) == "csv":
            secrets_dic["ak"] = SecretKeeper.__access__(self.secret_file)
            secrets_dic["sk"] = SecretKeeper.__secret__(self.secret_file)
            secrets_dic["reg"] = SecretKeeper.__region__(self.secret_file)
            secrets_dic["sg_id"] = SecretKeeper.__sg_id__(self.secret_file)
            return secrets_dic
        elif SecretKeeper.file_extension(self.secret_file) == "yaml":
            secrets_dic["ak"] = self.get_config["aliCloud"]["accessKeyId"]
            secrets_dic["sk"] = self.get_config["aliCloud"]["accessKeySecret"]
            secrets_dic["reg"] = self.get_config["aliCloud"]["region"]
            secrets_dic["sg_id"] = self.get_config["aliCloud"]["securityGroupId"]
            secrets_dic["protocol"] = self.get_config["aliCloud"]["monitorProtocol"]
            return secrets_dic
        else:
            raise ValueError("==> Unsupported file extension <==")

    @property
    def get_config(self) -> dict:
        config_res = SecretKeeper.__load__(file_name=self.secret_file)
        return config_res

    @staticmethod
    def __load__(file_name: str) -> dict:
        with open(file=file_name, mode="r", encoding="utf-8") as f:
            config_obj = yaml.safe_load(f)
            return config_obj

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
            ip_lst = [str(x).replace("\n","").lstrip("").rstrip("") for x in ip_f.readlines()]
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
    def is_in_sg_permissions(sg_api_data: dict,
                              protocol_method: str) -> bool:
        port_range = sg_api_data.get("PortRange")
        match protocol_method:
            case "ssh":
                if port_range == "1688":
                    return True
                elif port_range == "1688/1688":
                    return True
                else:
                    return False
            case "mysql":
                if port_range == "3306/3306":
                    return True
                elif port_range == "3306":
                    return True
                else:
                    return False
            case "https":
                if port_range == "443/443":
                    return True
                elif port_range == "443":
                    return True
                else:
                    return False
            case "http":
                if port_range == "80/80":
                    return True
                elif port_range == "80":
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
    def sg_details_parser(sg_api_data: dict, check_ip_addr: str,
                           monitor_protocol: list) -> None:
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
            logger.error("==> Parse API data error <==")

    async def get_sg_details_request(self, current_ip_addr: str) -> None:
        config = super().get_secrets()
        ak = config["ak"]
        sk = config["sk"]
        reg = config["reg"]
        sg_id = config["sg_id"]
        monitor_protocol = config["protocol"]
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
                ip_check_res = EcsSgManager.sg_details_parser(sg_api_data=sg_details_info,
                                                               check_ip_addr=current_ip_addr,
                                                               monitor_protocol=monitor_protocol[0])
                if ip_check_res:
                    EcsSgManager.write_ip_lst(ip_addr=current_ip_addr)
                    logger.info(ip_check_res)
                    logger.info("==> record local ip address <==")
                else:
                    perm_dict = dict()
                    perm_dict["policy"] = "accept"
                    perm_dict["priority"] = random.choice(range(1, 101))
                    perm_dict["ip_protocol"] = "TCP"
                    perm_dict["source_cidr_ip"] = f"{current_ip_addr.replace('\n', '').rstrip('').lstrip('')}/32"
                    perm_dict["portRange"] = "1688/1688"
                    perm_dict["description"] = f"work-from-home-ip-{dt.now().strftime('%Y%m%d-%H%M%S')}"
                    await self.create_sg_inbound(permissions_dic=perm_dict)
                    logger.info(perm_dict)
                    EcsSgManager.write_ip_lst(ip_addr=current_ip_addr)
                    logger.info("==> Record ip address in security group <==")
            else:
                sg_details_headers = json.dumps(sg_details_head.to_map(), indent=4)
                sg_details_headers_info = json.loads(sg_details_headers)
                logger.error(sg_details_headers_info)
                logger.error("Error occurred")

        except Exception as err:
            raise err

    async def create_sg_inbound(self, permissions_dic: dict) -> None:
        config = super().get_secrets()
        ak = config["ak"]
        sk = config["sk"]
        reg = config["reg"]
        sg_id = config["sg_id"]
        monitor_protocol = config["protocol"]
        for protocol in monitor_protocol:
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
                logger.error(err)

    async def sg_runner(self) -> None:
        ip_lst = EcsSgManager.read_ip_lst()
        current_ip_addr = GetLocalIpAddress.get_external_ip()
        formated_current_ip = f"{current_ip_addr.replace('\n', '').rstrip('').lstrip('')}"
        if [str(x).replace("\n","").lstrip("").rstrip("") for x in ip_lst if x in [formated_current_ip]]:
            logger.info("==> IP Exists <==")
            sys.exit(0)
        else:
            logger.warning("==> Ip address not record in local laptop <==")
            await self.get_sg_details_request(current_ip_addr)

if __name__ == '__main__':
    sg_manager = EcsSgManager(Path("./configurations/account.yaml"))
    asyncio.run(sg_manager.sg_runner())
