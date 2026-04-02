#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import hmac
import json
import math
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import time
import urllib.error
import urllib.request
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
from typing import Any, Dict, List, Optional

MODEL_IDS = [
    "hw_comp",
    "vt_comp_vm",
    "vt_sto_block",
    "vt_net_cloud_sub",
]

REGION = "wh"
BUSINESS_ZONE = "互金云"
SYNC_STATUS = "更新完成"

API_CONFIG = {
    "hosts": {
        "service": "opcvm",
        "version": "2019-06-25",
        "action": "DescribeHosts",
        "endpoint": "opcvm.yunapi3.cloud.hb96568.com",
        "limit": 100,
        "list_keys": ["HostSet","HostItem"],
    },
    "zones": {
        "service": "cvm",
        "version": "2017-03-12",
        "action": "DescribeZones",
        "endpoint": "cvm.yunapi3.cloud.hb96568.com",
        "limit": 100,
        "list_keys": ["ZoneSet"],
    },
    "instances": {
        "service": "opcvm",
        "version": "2019-06-25",
        "action": "DescribeInstances",
        "endpoint": "opcvm.yunapi3.cloud.hb96568.com",
        "limit": 100,
        "list_keys": ["InstanceSet", "InstancesSet"],
    },
    "disks": {
        "service": "cbs",
        "version": "2017-03-12",
        "action": "DescribeDisks",
        "endpoint": "cbs.yunapi3.cloud.hb96568.com",
        "limit": 100,
        "list_keys": ["DiskSet"],
    },
    "vpcs": {
        "service": "opvpc",
        "version": "2020-02-14",
        "action": "DescribeVpcEx",
        "endpoint": "opvpc.yunapi3.cloud.hb96568.com",
        "limit": 100,
        "list_keys": ["VpcSet"],
    },
}

CMDB_BROKER = "10.0.12.131:19341"
CMDB_HEADERS = {
    "Content-Type": "application/json",
    "Multi_language": "true",
    "withCredentials": "true",
    "accountId": "110",
    "userId": "1",
}
CMDB_V3_CONFIG = {
    "userId": 1,
    "tenantId": 110,
    "topTenantId": 110,
    "dataSourceId": "ITAM_API",
    "sig": "d9102ac8a4f797c65b8c7b5bd5c6c716",
}


class TencentYunRemote:
    """Tencent cloud asset sync collector based on requirement document."""

    def __init__(self, param: Dict[str, Any]):
        script_param = param.get("script", {}) if isinstance(param.get("script"), dict) else {}

        self.secret_id = self._pick_param(
            param,
            script_param,
            ["secret_id", "secret-id", "secretId", "SecretId", "script.secret_id", "script.secretId"],
        )
        self.secret_key = self._pick_param(
            param,
            script_param,
            ["secret_key", "secret-key", "secretKey", "SecretKey", "script.secret_key", "script.secretKey"],
        )
        self.secret_token = self._pick_param(
            param,
            script_param,
            [
                "secret_token",
                "secret-token",
                "secretToken",
                "token",
                "Token",
                "X-TC-Token",
                "script.secret_token",
                "script.secretToken",
                "script.token",
            ],
        )
        self.region = self._pick_param(
            param,
            script_param,
            ["region", "Region", "script.region"],
        ) or REGION
        self.cmdb_broker = self._pick_param(
            param,
            script_param,
            ["cmdb_broker", "cmdbBroker", "cmdbcms_broker", "script.cmdb_broker", "script.cmdbBroker"],
        ) or CMDB_BROKER
        cmdb_s_token = self._pick_param(
            param,
            script_param,
            ["cmdb_s_token", "s-token", "s_token", "script.cmdb_s_token", "script.s_token"],
        )
        self.cmdb_headers = dict(CMDB_HEADERS)
        if cmdb_s_token:
            self.cmdb_headers["s-token"] = cmdb_s_token

        cmdb_user_id = self._pick_param(
            param,
            script_param,
            ["cmdb_user_id", "cmdbUserId", "script.cmdb_user_id", "script.cmdbUserId"],
        )
        cmdb_tenant_id = self._pick_param(
            param,
            script_param,
            ["cmdb_tenant_id", "cmdbTenantId", "script.cmdb_tenant_id", "script.cmdbTenantId"],
        )
        cmdb_top_tenant_id = self._pick_param(
            param,
            script_param,
            ["cmdb_top_tenant_id", "cmdbTopTenantId", "script.cmdb_top_tenant_id", "script.cmdbTopTenantId"],
        )
        cmdb_data_source_id = self._pick_param(
            param,
            script_param,
            ["cmdb_data_source_id", "cmdbDataSourceId", "script.cmdb_data_source_id", "script.cmdbDataSourceId"],
        )
        cmdb_sig = self._pick_param(
            param,
            script_param,
            ["cmdb_sig", "script.cmdb_sig"],
        )

        self.cmdb_v3_config = dict(CMDB_V3_CONFIG)
        if cmdb_user_id:
            self.cmdb_v3_config["userId"] = int(cmdb_user_id)
            self.cmdb_headers["userId"] = str(cmdb_user_id)
        if cmdb_tenant_id:
            self.cmdb_v3_config["tenantId"] = int(cmdb_tenant_id)
            self.cmdb_headers["accountId"] = str(cmdb_tenant_id)
        if cmdb_top_tenant_id:
            self.cmdb_v3_config["topTenantId"] = int(cmdb_top_tenant_id)
        if cmdb_data_source_id:
            self.cmdb_v3_config["dataSourceId"] = cmdb_data_source_id
        if cmdb_sig:
            self.cmdb_v3_config["sig"] = cmdb_sig
        self.cmdb_query_url = f"http://{self.cmdb_broker}/api/v3/open/ci/getPageList"
        self.syncdate = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.completed = 0
        self.exceptions: List[str] = []

        if not self.secret_id or not self.secret_key:
            self.completed = 1
            self.exceptions.append("参数缺失: secret_id 和 secret_key 必填")

    @staticmethod
    def _pick_param(param: Dict[str, Any], script_param: Dict[str, Any], keys: List[str]) -> str:
        for key in keys:
            value = param.get(key)
            if value not in (None, ""):
                return str(value).strip().strip('"').strip("'")

        for key in keys:
            short_key = key.split(".")[-1]
            value = script_param.get(short_key)
            if value not in (None, ""):
                return str(value).strip().strip('"').strip("'")

        return ""

    @staticmethod
    def _sha256_hex(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _hmac_sha256(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _build_authorization(self, service: str, timestamp: int, canonical_request: str) -> str:
        date = datetime.datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")
        credential_scope = f"{date}/{service}/tc3_request"
        hashed_canonical_request = self._sha256_hex(canonical_request)
        string_to_sign = "\n".join(
            [
                "TC3-HMAC-SHA256",
                str(timestamp),
                credential_scope,
                hashed_canonical_request,
            ]
        )

        secret_date = self._hmac_sha256(("TC3" + self.secret_key).encode("utf-8"), date)
        secret_service = self._hmac_sha256(secret_date, service)
        secret_signing = self._hmac_sha256(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        return (
            f"TC3-HMAC-SHA256 Credential={self.secret_id}/{credential_scope}, "
            f"SignedHeaders=content-type;host, Signature={signature}"
        )

    def _call_api(self, service: str, endpoint: str, version: str, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = int(time.time())
        payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

        canonical_headers = f"content-type:application/json; charset=utf-8\nhost:{endpoint}\n"
        canonical_request = "\n".join(
            [
                "POST",
                "/",
                "",
                canonical_headers,
                "content-type;host",
                self._sha256_hex(payload_json),
            ]
        )

        authorization = self._build_authorization(service, timestamp, canonical_request)

        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Host": endpoint,
            "X-TC-Action": action,
            "X-TC-Version": version,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Region": self.region,
            "Authorization": authorization,
        }
        if self.secret_token:
            headers["X-TC-Token"] = self.secret_token

        req = urllib.request.Request(
            url=f"https://{endpoint}",
            data=payload_json.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw.strip() else {}

    def _extract_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(data, dict):
            return {}
        body = data.get("Response", {})
        if not isinstance(body, dict):
            return {}
        return body

    def _cmdb_query_ci_list(
        self,
        model_id: str,
        conditions: Optional[Any] = None,
        page_num: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        json_data: Dict[str, Any] = {
            **self.cmdb_v3_config,
            "modelId": model_id,
            "pageNum": max(1, int(page_num)),
            "pageSize": max(1, int(page_size)),
        }

        if conditions:
            if isinstance(conditions, dict):
                json_data["conditions"] = conditions
            elif isinstance(conditions, list):
                json_data["conditions"] = {
                    "conditionGroupOperator": "AND",
                    "conditionList": conditions,
                }

        try:
            req = urllib.request.Request(
                url=self.cmdb_query_url,
                data=json.dumps(json_data, ensure_ascii=False).encode("utf-8"),
                headers=self.cmdb_headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status != 200:
                    return {"success": False, "total": 0, "records": []}

                raw = resp.read().decode("utf-8", errors="replace")
                result = json.loads(raw) if raw.strip() else {}
                if result.get("code") != 0:
                    return {"success": False, "total": 0, "records": []}

                data = result.get("data") or {}
                return {
                    "success": True,
                    "total": data.get("total", 0),
                    "records": data.get("records") or [],
                    "totalPages": data.get("totalPages", 1),
                }
        except Exception:  # pylint: disable=broad-except
            return {"success": False, "total": 0, "records": []}

    def _cmdb_query_ci_all(
        self,
        model_id: str,
        conditions: Optional[Any] = None,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        all_records: List[Dict[str, Any]] = []
        page_num = 1
        safe_page_size = max(1, int(page_size))

        while True:
            page_data = self._cmdb_query_ci_list(
                model_id=model_id,
                conditions=conditions,
                page_num=page_num,
                page_size=safe_page_size,
            )
            if not page_data.get("success"):
                break

            records = page_data.get("records", [])
            if not isinstance(records, list) or not records:
                break

            all_records.extend([item for item in records if isinstance(item, dict)])

            total_pages_raw = page_data.get("totalPages", 1)
            total_raw = page_data.get("total", 0)
            try:
                total_pages = int(total_pages_raw)
            except (TypeError, ValueError):
                total_pages = 0
            try:
                total_count = int(total_raw)
            except (TypeError, ValueError):
                total_count = 0

            if total_pages > 0 and page_num >= total_pages:
                break
            if total_count > 0 and len(all_records) >= total_count:
                break
            if len(records) < safe_page_size:
                break

            page_num += 1

        return all_records

    @staticmethod
    def _cmdb_get_record_field(record: Dict[str, Any], field: str) -> Any:
        if not isinstance(record, dict):
            return ""

        if field in record:
            return record.get(field)

        content = record.get("content")
        if isinstance(content, dict):
            return content.get(field, "")

        return ""

    def _cmdb_records_to_dict(
        self,
        records: List[Dict[str, Any]],
        key_field: str,
        value_field: str,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            key = str(self._cmdb_get_record_field(record, key_field) or "").strip()
            if not key:
                continue
            result[key] = self._cmdb_get_record_field(record, value_field)
        return result

    def _cmdb_query_dict(
        self,
        model_id: str,
        key_field: str,
        value_field: str,
        conditions: Optional[Any] = None,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        records = self._cmdb_query_ci_all(model_id=model_id, conditions=conditions, page_size=page_size)
        return self._cmdb_records_to_dict(records=records, key_field=key_field, value_field=value_field)

    def _cmdb_query_dict_candidates(
        self,
        model_ids: List[str],
        key_field: str,
        value_field: str,
        conditions: Optional[Any] = None,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        for model_id in model_ids:
            if not model_id:
                continue
            result = self._cmdb_query_dict(
                model_id=model_id,
                key_field=key_field,
                value_field=value_field,
                conditions=conditions,
                page_size=page_size,
            )
            if isinstance(result, dict) and result:
                merged.update(result)
                break
        return merged

    @staticmethod
    def _extract_list(body: Dict[str, Any], list_keys: List[str]) -> List[Dict[str, Any]]:
        for key in list_keys:
            value = body.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []

    def _fetch_all(self, key: str) -> List[Dict[str, Any]]:
        conf = API_CONFIG[key]
        offset = 0
        limit = max(1, min(int(conf.get("limit", 100)), 100))
        result: List[Dict[str, Any]] = []

        while True:
            payload = {"Limit": limit, "Offset": offset}
            body = self._safe_call(
                service=str(conf["service"]),
                endpoint=str(conf["endpoint"]),
                version=str(conf["version"]),
                action=str(conf["action"]),
                payload=payload,
            )
            if body is None:
                break

            items = self._extract_list(body, conf.get("list_keys", []))
            if not items:
                break

            result.extend(items)
            total = body.get("TotalCount",body.get("total"))

            if len(items) < limit:
                break

            offset += limit
            if isinstance(total, int) and offset >= total:
                break

        return result

    def _safe_call(
        self,
        service: str,
        endpoint: str,
        version: str,
        action: str,
        payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        try:
            data = self._call_api(service, endpoint, version, action, payload)
            body = self._extract_response(data)
            error_obj = body.get("Error") if isinstance(body, dict) else None
            if error_obj:
                code = error_obj.get("Code", "Unknown")
                message = error_obj.get("Message", "")
                self.completed = 1
                if str(code) == "AuthFailure.SignatureFailure":
                    message = f"{message} (请检查 SecretId/SecretKey 是否正确)"
                self.exceptions.append(f"{action} 调用失败: {code} {message}")
                return None
            return body
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", errors="replace") if err.fp else ""
            self.completed = 1
            self.exceptions.append(f"{action} HTTP错误 {err.code}: {raw[:300]}")
        except urllib.error.URLError as err:
            self.completed = 1
            self.exceptions.append(f"{action} 网络错误: {err}")
        except Exception as err:  # pylint: disable=broad-except
            self.completed = 1
            self.exceptions.append(f"{action} 执行异常: {err}")
        return None

    def _build_zone_map(self) -> Dict[str, Dict[str, Any]]:
        body = self._safe_call(
            service=API_CONFIG["zones"]["service"],
            endpoint=API_CONFIG["zones"]["endpoint"],
            version=API_CONFIG["zones"]["version"],
            action=API_CONFIG["zones"]["action"],
            payload={},
        )
        if not body:
            return {}

        zones = self._extract_list(body, API_CONFIG["zones"].get("list_keys", []))
        if not zones:
            return {}

        zone_map: Dict[str, Dict[str, Any]] = {}
        for zone in zones:
            zone_id = str(zone.get("ZoneId", ""))
            if zone_id:
                zone_map[zone_id] = zone
        return zone_map

    @staticmethod
    def _mcpu_to_core(value: Any) -> Any:
        if value in (None, "", [], {}):
            return ""
        try:
            scaled = Decimal(str(value)) / Decimal("1000")
            return float(scaled.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        except (TypeError, ValueError, InvalidOperation):
            return ""

    @staticmethod
    def _round_numeric(value: Any) -> Any:
        if value in (None, "", [], {}):
            return ""
        try:
            decimal_value = Decimal(str(value))
            return float(decimal_value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        except (TypeError, ValueError, InvalidOperation):
            return ""

    @staticmethod
    def _mb_to_gb(value: Any) -> Any:
        if value in (None, "", [], {}):
            return ""
        try:
            scaled = Decimal(str(value)) / Decimal("1024")
            return float(scaled.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        except (TypeError, ValueError, InvalidOperation):
            return ""

    @staticmethod
    def _first_ip(value: Any) -> str:
        if isinstance(value, list):
            for item in value:
                text = str(item).strip()
                if text:
                    return text
            return ""
        if isinstance(value, str):
            return value.split(",")[0].strip()
        return ""

    @staticmethod
    def _host_status_map(status: Any) -> str:
        mapping = {
            "NORMAL": "active",
            "ABNORMAL": "error",
            "STOP": "stop",
        }
        key = str(status or "").strip().upper()
        return mapping.get(key, str(status or ""))

    @staticmethod
    def _vm_status_map(status: Any) -> str:
        text = str(status or "").strip()
        return "active" if text == "3" else "other"

    @staticmethod
    def _disk_state_map(status: Any) -> str:
        mapping = {
            "ATTACHED": "使用中",
            "已挂载": "使用中",
            "DETACHED": "可用",
            "未挂载": "可用",
            "CREATING": "其他",
            "DELETING": "其他",
            "创建中": "其他",
            "删除中": "其他",
        }
        raw = str(status or "").strip()
        key = raw.upper()
        if raw in mapping:
            return mapping[raw]
        return mapping.get(key, str(status or ""))

    @staticmethod
    def _network_type_map(network_type: Any) -> str:
        key = str(network_type or "").strip().upper()
        if key == "VPC":
            return "overlay"
        if key == "CLASSIC":
            return "underlay"
        return ""

    def _map_hosts(self, hosts: List[Dict[str, Any]], zone_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for host in hosts:
            host_resource = host.get("HostResource", {}) if isinstance(host.get("HostResource"), dict) else {}

            cpu_total = host_resource.get("CpuTotal", "")
            cpu_available = host_resource.get("CpuAvailable", "")
            mem_total = host_resource.get("MemoryTotal", "")
            mem_available = host_resource.get("MemoryAvailable", "")
            disk_total = host_resource.get("DiskTotal", "")
            disk_available = host_resource.get("DiskAvailable", "")

            allocated_cpu = ""
            allocated_memory = ""
            allocated_disk = ""
            try:
                allocated_cpu = self._mcpu_to_core(float(cpu_total) - float(cpu_available))
            except (TypeError, ValueError):
                allocated_cpu = ""
            try:
                allocated_memory = self._mb_to_gb(float(mem_total) - float(mem_available))
            except (TypeError, ValueError):
                allocated_memory = ""
            try:
                allocated_disk = self._round_numeric(float(disk_total) - float(disk_available))
            except (TypeError, ValueError):
                allocated_disk = ""

            zone_id = str(host.get("ZoneId", ""))
            zone_name = ""
            if zone_id and zone_id in zone_map:
                zone_name = str(zone_map[zone_id].get("ZoneName", ""))

            row = {
                "device_id": host.get("HostAsset", ""),
                "ci_name": host.get("HostAsset", ""),
                "ip_address": host.get("HostIp", ""),
                "resourcepoolid": host.get("Pool", ""),
                "resourcepoolname": host.get("Pool", ""),
                "azoneid": zone_id,
                "azonename": zone_name,
                "sku": host.get("HostType", ""),
                "yxzt": self._host_status_map(host.get("HostStatus", "")),
                "total_disk_capacity": self._round_numeric(disk_total),
                "vcpu_count": self._mcpu_to_core(cpu_total),
                "freevcpucores": self._mcpu_to_core(cpu_available),
                "allocatedvcpucores": allocated_cpu,
                "virtual_memory": self._mb_to_gb(mem_total),
                "allocatedvmemory": allocated_memory,
                "freevmemory": self._mb_to_gb(mem_available),
                "allocateddisksize": allocated_disk,
                "freedisksize": self._round_numeric(disk_available),
                "netlayertype": self._network_type_map(host.get("NetworkType", "")),
                "businesszone": BUSINESS_ZONE,
                "syncstatus": SYNC_STATUS,
            }
            rows.append({k: v for k, v in row.items() if v not in (None, "", [])})
        return rows

    @staticmethod
    def _sum_disk_size(instance: Dict[str, Any]) -> Any:
        total = 0.0
        has_any = False

        system_disk = instance.get("SystemDisk", {})
        if isinstance(system_disk, dict):
            value = system_disk.get("DiskSize")
            try:
                total += float(value)
                has_any = True
            except (TypeError, ValueError):
                pass

        data_disks = instance.get("DataDisks", [])
        if isinstance(data_disks, list):
            for disk in data_disks:
                if not isinstance(disk, dict):
                    continue
                value = disk.get("DiskSize")
                try:
                    total += float(value)
                    has_any = True
                except (TypeError, ValueError):
                    continue

        if not has_any:
            return ""
        return TencentYunRemote._round_numeric(total)

    def _map_instances(
        self,
        instances: List[Dict[str, Any]],
        host_by_ip: Dict[str, Dict[str, Any]],
        zone_map: Dict[str, Dict[str, Any]],
        vpc_name_map: Dict[str, str],
        host_ci_id_map: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for instance in instances:
            host_ip = str(instance.get("HostIp", "")).strip()
            host = host_by_ip.get(host_ip, {})
            host_asset = str(host.get("HostAsset", "")).strip()
            host_ci_id = str(host_ci_id_map.get(host_asset, "")).strip() if host_asset else ""

            zone_id = str(host.get("ZoneId", instance.get("ZoneId", "")))
            zone_name = ""
            if zone_id and zone_id in zone_map:
                zone_name = str(zone_map[zone_id].get("ZoneName", ""))

            vpc_id = str(instance.get("VirtualPrivateCloudId", ""))
            os_name = str(instance.get("OsName", ""))
            instance_uuid = str(instance.get("InstanceId", "")).strip()

            # 调试日志：打印虚拟机 InstanceId 用于对比
            print(f"[DEBUG] VM: InstanceId={instance_uuid}")

            row = {
                "ci_name": instance.get("InstanceName", ""),
                "instance_id": instance_uuid,
                "ip_address": self._first_ip(instance.get("PrivateIpAddress", "")),
                "resourcepoolid": host.get("Pool", ""),
                "resourcepoolname": host.get("Pool", ""),
                "azoneid": zone_id,
                "azonename": zone_name,
                "clusterid": vpc_name_map.get(vpc_id, ""),
                "clustername": vpc_id,
                "yxzt": self._vm_status_map(instance.get("vmState", instance.get("Status", ""))),
                "physical_host": host_ci_id,
                "os_type": "windows" if "win" in os_name.lower() else "linux",
                "osversion": os_name,
                "vcpu_count": self._mcpu_to_core(instance.get("CPU", "")),
                "virtual_memory": self._mb_to_gb(instance.get("Memory", "")),
                "disk_capacity": self._sum_disk_size(instance),
                "netlayertype": self._network_type_map(instance.get("NetworkType", host.get("NetworkType", ""))),
                "businesszone": BUSINESS_ZONE,
                "tenantid": instance.get("Owner", ""),
                "syncstatus": SYNC_STATUS,
            }
            rows.append({
                k: v for k, v in row.items() if v not in (None, "", []) or k in ("physical_host",)
            })
        return rows

    def _map_disks(
        self,
        disks: List[Dict[str, Any]],
        host_by_ip: Dict[str, Dict[str, Any]],
        vm_ci_id_map: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for disk in disks:
            # 核心逻辑：通过 InstanceUuid 查找对应的 CMDB ciId
            # 注意：腾讯云的 InstanceUuid 对应 CMDB 虚拟机的 instance_id 字段
            vm_instance_id = str(disk.get("InstanceUuid", "")).strip()
            vm_ci_id = ""
            map_exists = False
            
            if vm_instance_id:
                vm_ci_id = str(vm_ci_id_map.get(vm_instance_id, "")).strip()
                map_exists = vm_instance_id in vm_ci_id_map
                if not vm_ci_id:
                    logger.warning(f"Disk {disk.get('DiskId', '')} has InstanceUuid {vm_instance_id}, but no matching VM found in CMDB (map_exists={map_exists})")
            else:
                logger.info(f"Disk {disk.get('DiskId', '')} is not attached to any VM (InstanceUuid is empty)")
            
            # 构建调试信息用于 tagtagtag
            debug_info = {
                "disk_id": disk.get("DiskId", ""),
                "instance_uuid": vm_instance_id,
                "vm_ci_id_found": vm_ci_id,
                "vm_ci_id_map_has_key": map_exists,
                "vm_ci_id_map_keys_count": len(vm_ci_id_map),
            }

            row = {
                "ci_name": disk.get("DiskName", ""),
                "instance_id": disk.get("DiskId", ""),
                "resourcepoolid": host.get("Pool", ""),
                "resourcepoolname": host.get("Pool", ""),
                "azoneid": placement.get("ZoneId", ""),
                "azonename": placement.get("Zone", ""),
                "efective_capacity": self._round_numeric(disk.get("DiskSize", "")),
                "managervolume": "true" if disk_usage == "SYSTEM_DISK" else "false",
                "vmid": vm_ci_id,
                "zczt": self._disk_state_map(disk.get("DiskState", "")),
                "volumetype": disk.get("DiskType", ""),
                "businesszone": BUSINESS_ZONE,
                "syncstatus": SYNC_STATUS,
                "tagtagtag": debug_info,
            }
            rows.append({
                k: v for k, v in row.items() if v not in (None, "", []) or k in ("vmid",)
            })
            
            # 输出结构化调试日志 (格式参考 vt_net_cloud_sub)
            debug_log_entry = {
                "content": {
                    "disk_id": disk.get("DiskId", ""),
                    "instance_uuid": vm_instance_id,
                    "vm_ci_id_found": vm_ci_id if vm_ci_id else None,
                    "map_lookup_key": vm_instance_id,
                    "map_exists": map_exists,
                    "total_vm_in_map": len(vm_ci_id_map)
                },
                "modelId": "debug_vm_disk_mapping",
                "completed": 0,
                "exceptions": []
            }
            # 使用 info 级别输出，确保能在平台日志中看到
            logger.info(f"[DEBUG_MAPPING] {json.dumps(debug_log_entry, ensure_ascii=False)}")
        return rows

    @staticmethod
    def _map_vpcs(vpcs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for vpc in vpcs:
            row = {
                "ci_name": vpc.get("VpcName", ""),
                "instance_id": vpc.get("VpcId", ""),
                "cidrblock": vpc.get("CidrBlock", ""),
                "rtbnum": vpc.get("RtbNum", ""),
                "subnetnum": vpc.get("SubnetNum", ""),
                "vpcpeernum": vpc.get("VpcPeerNum", ""),
                "vpgnum": vpc.get("VpgNum", ""),
                "vpngwnum": vpc.get("VpngwNum", ""),
                "vmnum": vpc.get("VmNum", ""),
                "natnum": vpc.get("NatNum", ""),
                "aclnum": vpc.get("AclNum", ""),
                "businesszone": BUSINESS_ZONE,
                "tenantid": vpc.get("Owner", ""),
                "syncstatus": SYNC_STATUS,
            }
            rows.append({k: v for k, v in row.items() if v not in (None, "", [])})
        return rows

    def _model_result(self, model_id: str, content: Dict[str, Any]) -> Dict[str, Any]:
        content_with_syncdate = dict(content) if isinstance(content, dict) else {}
        content_with_syncdate["syncdate"] = self.syncdate
        return {
            "content": content_with_syncdate,
            "modelId": model_id,
            "completed": self.completed,
            "exceptions": self.exceptions,
        }

    def _group_model_results(self, assets: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []

        for model_id in MODEL_IDS:
            rows = assets.get(model_id, [])
            if rows:
                # 将同一个 model_id 的所有记录合并到一个对象中
                result.append({
                    "content": {
                        "records": rows,
                        "syncdate": self.syncdate,
                    },
                    "modelId": model_id,
                    "completed": self.completed,
                    "exceptions": self.exceptions,
                })
            else:
                result.append(self._model_result(model_id, {}))

        return result

    def result(self) -> None:
        assets = {model_id: [] for model_id in MODEL_IDS}

        if self.completed == 0:
            host_ci_id_map = self._cmdb_query_dict_candidates(
                model_ids=["mod_hw", "mod_hw_comp", "hw_comp"],
                key_field="device_id",
                value_field="ciId",
                conditions=[
                    {
                        "field": "device_id",
                        "operator": "NOT_NULL",
                        "value": "",
                    }
                ],
            )
            vm_ci_id_map = self._cmdb_query_dict_candidates(
                model_ids=["mod_vm", "mod_vt_comp_vm", "vt_comp_vm"],
                key_field="instance_id",
                value_field="ciId",
                conditions=[
                    {
                        "field": "instance_id",
                        "operator": "NOT_NULL",
                        "value": "",
                    }
                ],
            )
            hosts = self._fetch_all("hosts")
            if not hosts:
                self.exceptions.append(
                        "hw_comp 为空: DescribeHosts 返回 0 条数据，请检查 region、账号权限或资源类型"
                )
            host_by_ip = {
                str(item.get("HostIp", "")).strip(): item
                for item in hosts
                if isinstance(item, dict) and str(item.get("HostIp", "")).strip()
            }

            zone_map = self._build_zone_map()
            instances = self._fetch_all("instances")
            disks = self._fetch_all("disks")
            vpcs = self._fetch_all("vpcs")
            vpc_name_map = {
                str(item.get("VpcId", "")): str(item.get("VpcName", ""))
                for item in vpcs
                if isinstance(item, dict) and item.get("VpcId") not in (None, "")
            }

            assets["hw_comp"] = self._map_hosts(hosts, zone_map)
            assets["vt_comp_vm"] = self._map_instances(
                instances,
                host_by_ip,
                zone_map,
                vpc_name_map,
                host_ci_id_map,
            )
            assets["vt_sto_block"] = self._map_disks(disks, host_by_ip, vm_ci_id_map)
            assets["vt_net_cloud_sub"] = self._map_vpcs(vpcs)

        result = self._group_model_results(assets)
        print(json.dumps(result, indent=4, ensure_ascii=False))


if __name__ == "__main__":
 

    try:
        json_parameters = json.loads(json_string)
        parameters = json_parameters.get("parameters", {})
        TencentYunRemote(parameters).result()
    except json.JSONDecodeError as err:
        print(
            json.dumps(
                [
                    {
                        "content": {},
                        "modelId": model_id,
                        "completed": 1,
                        "exceptions": [f"JSON解析失败: {err}"],
                    }
                    for model_id in MODEL_IDS
                ],
                indent=4,
                ensure_ascii=False,
            )
        )
    except Exception as err:  # pylint: disable=broad-except
        print(
            json.dumps(
                [
                    {
                        "content": {},
                        "modelId": model_id,
                        "completed": 1,
                        "exceptions": [f"执行异常: {err}"],
                    }
                    for model_id in MODEL_IDS
                ],
                indent=4,
                ensure_ascii=False,
            )
        )
