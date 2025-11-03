"""
AWS EC2 관리 핵심 로직
UI와 독립적으로 작동 → 테스트 가능
"""
import boto3
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class EC2Instance:
    """EC2 인스턴스 정보"""
    def __init__(self, instance_id: str, name: str, status: str, 
                 instance_type: str, region: str,
                 termination_protection: bool = False,
                 stop_protection: bool = False):
        self.id = instance_id
        self.name = name
        self.status = status
        self.type = instance_type
        self.region = region
        self.termination_protection = termination_protection
        self.stop_protection = stop_protection
    
    def to_dict(self) -> Dict:
        """딕셔너리로 변환"""
        return {
            'id': self.id,
            'name': self.name,
            'status': self.status,
            'type': self.type,
            'region': self.region,
            'termination_protection': self.termination_protection,
            'stop_protection': self.stop_protection
        }


class EC2Manager:
    """AWS EC2 관리 클래스 (비즈니스 로직만)"""
    
    REGION_NAMES = {
        'us-east-1': 'N. Virginia',
        'us-east-2': 'Ohio',
        'us-west-1': 'N. California',
        'us-west-2': 'Oregon',
        'ap-south-1': 'Mumbai',
        'ap-northeast-1': 'Tokyo',
        'ap-northeast-2': 'Seoul',
        'ap-northeast-3': 'Osaka',
        'ap-southeast-1': 'Singapore',
        'ap-southeast-2': 'Sydney',
        'ap-southeast-3': 'Jakarta',
        'ap-southeast-4': 'Melbourne',
        'ap-east-1': 'Hong Kong',
        'ca-central-1': 'Canada',
        'ca-west-1': 'Calgary',
        'eu-central-1': 'Frankfurt',
        'eu-central-2': 'Zurich',
        'eu-west-1': 'Ireland',
        'eu-west-2': 'London',
        'eu-west-3': 'Paris',
        'eu-north-1': 'Stockholm',
        'eu-south-1': 'Milan',
        'eu-south-2': 'Spain',
        'me-south-1': 'Bahrain',
        'me-central-1': 'UAE',
        'sa-east-1': 'São Paulo',
        'af-south-1': 'Cape Town',
        'il-central-1': 'Tel Aviv'
    }
    
    def __init__(self, access_key: str, secret_key: str):
        self.access_key = access_key
        self.secret_key = secret_key
        self._regions_cache = None
    
    def create_client(self, region: str):
        """EC2 클라이언트 생성"""
        return boto3.client(
            'ec2',
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=region
        )
    
    def get_available_regions(self) -> List[str]:
        """사용 가능한 AWS 리전 목록"""
        if self._regions_cache:
            return self._regions_cache
        
        ec2 = self.create_client('us-east-1')
        response = ec2.describe_regions()
        self._regions_cache = [r['RegionName'] for r in response['Regions']]
        return self._regions_cache
    
    def get_instances_in_region(self, region: str) -> List[EC2Instance]:
        """특정 리전의 인스턴스 조회"""
        ec2 = self.create_client(region)
        response = ec2.describe_instances()
        
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances.append(self._parse_instance(instance, region))
        
        # Protection 정보 병렬 조회
        self._fetch_protection_info(instances)
        
        return instances
    
    def get_all_instances(self, regions: Optional[List[str]] = None) -> List[EC2Instance]:
        """모든 리전의 인스턴스 조회 (병렬)"""
        if not regions:
            regions = self.get_available_regions()
        
        all_instances = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_region = {
                executor.submit(self.get_instances_in_region, region): region 
                for region in regions
            }
            
            for future in as_completed(future_to_region):
                try:
                    instances = future.result()
                    all_instances.extend(instances)
                except Exception:
                    # 특정 리전 실패해도 계속 진행
                    pass
        
        return all_instances
    
    def start_instances(self, instance_ids: List[str], region: str):
        """인스턴스 시작"""
        ec2 = self.create_client(region)
        ec2.start_instances(InstanceIds=instance_ids)
    
    def stop_instances(self, instance_ids: List[str], region: str):
        """인스턴스 중지"""
        ec2 = self.create_client(region)
        ec2.stop_instances(InstanceIds=instance_ids)
    
    def terminate_instances(self, instance_ids: List[str], region: str):
        """인스턴스 삭제"""
        ec2 = self.create_client(region)
        ec2.terminate_instances(InstanceIds=instance_ids)
    
    def set_termination_protection(self, instance_id: str, region: str, enabled: bool):
        """Termination Protection 설정"""
        ec2 = self.create_client(region)
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': enabled}
        )
    
    def set_stop_protection(self, instance_id: str, region: str, enabled: bool):
        """Stop Protection 설정"""
        ec2 = self.create_client(region)
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiStop={'Value': enabled}
        )
    
    def _parse_instance(self, instance: Dict, region: str) -> EC2Instance:
        """AWS 응답을 EC2Instance 객체로 변환"""
        name = ''
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                name = tag['Value']
                break
        
        return EC2Instance(
            instance_id=instance['InstanceId'],
            name=name,
            status=instance['State']['Name'],
            instance_type=instance['InstanceType'],
            region=region
        )
    
    def _fetch_protection_info(self, instances: List[EC2Instance]):
        """Protection 정보 병렬 조회"""
        def fetch_protection(inst: EC2Instance):
            try:
                ec2 = self.create_client(inst.region)
                
                # Termination protection
                resp = ec2.describe_instance_attribute(
                    InstanceId=inst.id, 
                    Attribute='disableApiTermination'
                )
                inst.termination_protection = resp.get('DisableApiTermination', {}).get('Value', False)
                
                # Stop protection
                resp = ec2.describe_instance_attribute(
                    InstanceId=inst.id,
                    Attribute='disableApiStop'
                )
                inst.stop_protection = resp.get('DisableApiStop', {}).get('Value', False)
            except Exception:
                pass
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(fetch_protection, instances)
    
    @staticmethod
    def get_region_display_name(region_code: str) -> str:
        """리전 코드 → 표시명"""
        if region_code in EC2Manager.REGION_NAMES:
            return f"{region_code} ({EC2Manager.REGION_NAMES[region_code]})"
        return region_code
    
    @staticmethod
    def extract_region_code(region_display: str) -> str:
        """표시명 → 리전 코드"""
        return region_display.split(' (')[0] if ' (' in region_display else region_display
