import tkinter as tk
from tkinter import messagebox, ttk
import boto3
import threading
import json
import os
from cryptography.fernet import Fernet
import hashlib
import uuid
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

class App:
    WINDOW_WIDTH = 1200
    WINDOW_HEIGHT = 550
    AUTO_REFRESH_INTERVAL = 3.0
    AUTO_REFRESH_MAX_COUNT = 30
    TRANSITIONING_STATES = ['pending', 'stopping', 'shutting-down', 'terminating']
    
    # AWS 리전명 매핑
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
    
    def __init__(self, root):
        self.root = root
        self.root.title("EC2 Controller")
        self.root.geometry(f"{self.WINDOW_WIDTH}x{self.WINDOW_HEIGHT}")
        self.root.resizable(True, True)
        self.root.minsize(1000, 450)
        self.instances = []
        self.key = None
        self.secret = None
        self.regions = []
        self.config_file = os.path.join(os.path.expanduser("~"), ".aws_ctrl_cfg")
        self.setup_crypto()
        self.auto_refresh_timer = None
        self.auto_refresh_count = 0
        self.checked = set()
        
        self.status = tk.Label(root, text="Login required (Click checkbox for select)")
        self.status.pack(side=tk.BOTTOM, pady=5)
        
        self.setup_control_buttons()
        self.setup_login_ui()
        self.setup_instance_list_ui()
        
        self.load_config()
    
    def get_region_display_name(self, region_code):  # 리전 코드를 표시용 이름으로 변환 (예: ap-northeast-2 -> ap-northeast-2 (Seoul))
        if region_code in self.REGION_NAMES:
            return f"{region_code} ({self.REGION_NAMES[region_code]})"
        return region_code
    
    def extract_region_code(self, region_display):  # 표시용 리전명에서 실제 리전 코드 추출
        return region_display.split(' (')[0] if ' (' in region_display else region_display
    
    def create_ec2_client(self, region):
        return boto3.client('ec2',
            aws_access_key_id=self.key,
            aws_secret_access_key=self.secret,
            region_name=region
        )
    
    def get_instance_name(self, instance):
        return next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), '')
    
    def create_instance_dict(self, instance, region, termination_protection=False, stop_protection=False):
        return {
            'id': instance['InstanceId'],
            'name': self.get_instance_name(instance),
            'status': instance['State']['Name'],
            'type': instance['InstanceType'],
            'region': region,
            'termination_protection': termination_protection,
            'stop_protection': stop_protection
        }
    
    def update_status(self, text):
        self.root.after(0, lambda: self.status.config(text=text))
    
    def setup_login_ui(self):
        login_ui = tk.Frame(self.root)
        login_ui.pack(side=tk.TOP, pady=10, fill=tk.X, padx=20)
        
        tk.Label(login_ui, text="Access Key:").grid(row=0, column=0, sticky=tk.W)
        self.key_input = tk.Entry(login_ui, width=40)
        self.key_input.grid(row=0, column=1, padx=5)
        
        tk.Label(login_ui, text="Secret Key:").grid(row=1, column=0, sticky=tk.W)
        self.secret_input = tk.Entry(login_ui, width=40, show="*")
        self.secret_input.grid(row=1, column=1, padx=5)
        
        self.login_btn = tk.Button(login_ui, text="Login", command=self.login)
        self.login_btn.grid(row=2, column=1, pady=10, sticky=tk.E)
    
    def setup_instance_list_ui(self):
        list_ui = tk.Frame(self.root)
        list_ui.pack(side=tk.TOP, pady=10, fill=tk.BOTH, expand=True, padx=20)
        
        filter_ui = tk.Frame(list_ui)
        filter_ui.pack(fill=tk.X, pady=5)
        
        tk.Label(filter_ui, text="Instances:").pack(side=tk.LEFT)
        tk.Label(filter_ui, text="Region:").pack(side=tk.LEFT, padx=(20, 5))
        
        self.region_filter = ttk.Combobox(filter_ui, width=30, state="readonly")
        self.region_filter['values'] = ['ALL']
        self.region_filter.current(0)
        self.region_filter.pack(side=tk.LEFT)
        self.region_filter.bind('<<ComboboxSelected>>', lambda e: self.filter_instances())
        
        tree_frame = tk.Frame(list_ui)  # Treeview와 스크롤바를 담을 프레임
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")  # 세로 스크롤바
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")  # 가로 스크롤바
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tree = ttk.Treeview(  # height 파라미터 제거하여 창 크기에 따라 자동 조절
            tree_frame, 
            columns=('check', 'term_protect', 'stop_protect', 'id', 'name', 'status', 'type', 'region'), 
            show='headings', 
            selectmode='extended',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        self.tree.heading('check', text='Select')
        self.tree.heading('term_protect', text='Termination Lock')
        self.tree.heading('stop_protect', text='Stop Lock')
        self.tree.heading('id', text='Instance ID')
        self.tree.heading('name', text='Name')
        self.tree.heading('status', text='Status')
        self.tree.heading('type', text='Type')
        self.tree.heading('region', text='Region')
        
        self.tree.column('check', width=60, minwidth=50, stretch=tk.NO, anchor='center')
        self.tree.column('term_protect', width=120, minwidth=100, stretch=tk.YES, anchor='center')
        self.tree.column('stop_protect', width=120, minwidth=100, stretch=tk.YES, anchor='center')
        self.tree.column('id', width=170, minwidth=150, stretch=tk.YES)
        self.tree.column('name', width=140, minwidth=100, stretch=tk.YES)
        self.tree.column('status', width=100, minwidth=80, stretch=tk.YES)
        self.tree.column('type', width=120, minwidth=100, stretch=tk.YES)
        self.tree.column('region', width=250, minwidth=200, stretch=tk.YES)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.tree.bind('<Button-1>', self.on_tree_click)
    
    def setup_control_buttons(self):
        btn_ui = tk.Frame(self.root)
        btn_ui.pack(side=tk.BOTTOM, pady=10)
        
        buttons = [
            ("Refresh", self.refresh),
            ("All Refresh", self.refresh_all),
            ("Start", self.start_instance),
            ("Stop", self.stop_instance),
            ("Terminate", self.terminate_instance)
        ]
        
        self.control_buttons = []
        for text, command in buttons:
            btn = tk.Button(btn_ui, text=text, command=command, state=tk.DISABLED)
            if text == "Terminate":
                btn.config(fg='red')
            btn.pack(side=tk.LEFT, padx=5)
            self.control_buttons.append(btn)
    
    def on_tree_click(self, event):
        if self.tree.identify_region(event.x, event.y) != 'cell':
            return
        
        column = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)
        if not item:
            return
        
        values = list(self.tree.item(item)['values'])
        
        if column == '#1':  # Select 컬럼
            if item in self.checked:
                self.checked.remove(item)
                values[0] = '☐'
            else:
                self.checked.add(item)
                values[0] = '☑'
            self.tree.item(item, values=values)
        
        elif column in ('#2', '#3'):  # Termination Lock 또는 Stop Lock 컬럼
            instance_id = values[3]
            region = self.extract_region_code(values[7])
            protection_type = 'termination' if column == '#2' else 'stop'
            index = 1 if column == '#2' else 2
            current_state = values[index] == '☑'
            self.toggle_protection(instance_id, region, protection_type, not current_state)
    
    def setup_crypto(self):
        pc_id = str(uuid.getnode())
        key_bytes = hashlib.sha256(pc_id.encode()).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(key_bytes))
    
    def encode(self, data):
        return self.cipher.encrypt(data.encode()).decode()
    
    def decode(self, data):
        return self.cipher.decrypt(data.encode()).decode()
    
    def toggle_protection(self, instance_id, region, protection_type, enable):
        def run():
            try:
                ec2 = self.create_ec2_client(region)
                
                if protection_type == 'termination':
                    ec2.modify_instance_attribute(
                        InstanceId=instance_id,
                        DisableApiTermination={'Value': enable}
                    )
                    protection_name = 'Termination Protection'
                else:  # stop
                    ec2.modify_instance_attribute(
                        InstanceId=instance_id,
                        DisableApiStop={'Value': enable}
                    )
                    protection_name = 'Stop Protection'
                
                for inst in self.instances:  # 로컬 리스트 즉시 업데이트
                    if inst['id'] == instance_id:
                        if protection_type == 'termination':
                            inst['termination_protection'] = enable
                        else:
                            inst['stop_protection'] = enable
                        break
                
                self.root.after(0, lambda: self.refresh_specific_region(region))  # 해당 리전만 재조회
                action = "enabled" if enable else "disabled"
                self.update_status(f"{protection_name} {action} for {instance_id}")  # 상태바에만 표시
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def save_config(self):
        if self.key and self.secret:
            try:
                cfg = {'k': self.encode(self.key), 's': self.encode(self.secret)}
                with open(self.config_file, 'w') as f:
                    json.dump(cfg, f)
            except Exception:
                pass
    
    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    cfg = json.load(f)
                key = self.decode(cfg['k'])
                secret = self.decode(cfg['s'])
                self.key_input.insert(0, key)
                self.secret_input.insert(0, secret)
        except Exception:
            pass
    
    def login(self):
        key = self.key_input.get().strip()
        secret = self.secret_input.get().strip()
        
        if not key or not secret:
            messagebox.showwarning("Warning", "Enter all credentials")
            return
        
        def run():
            try:
                self.key = key
                self.secret = secret
                
                self.update_status("Loading regions...")
                ec2 = boto3.client('ec2', aws_access_key_id=key, aws_secret_access_key=secret, region_name='us-east-1')
                resp = ec2.describe_regions()
                self.regions = [r['RegionName'] for r in resp['Regions']]
                
                self.save_config()
                
                for btn in self.control_buttons:
                    self.root.after(0, lambda b=btn: b.config(state=tk.NORMAL))
                
                self.root.after(0, lambda: self.login_btn.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.key_input.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.secret_input.config(state=tk.DISABLED))
                
                self.root.after(0, self.refresh_all)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Login Failed", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def check_and_auto_refresh(self):
        if self.auto_refresh_timer:
            self.root.after_cancel(self.auto_refresh_timer)
            self.auto_refresh_timer = None
        
        has_transitioning = any(inst['status'] in self.TRANSITIONING_STATES for inst in self.instances)
        
        if has_transitioning and self.auto_refresh_count < self.AUTO_REFRESH_MAX_COUNT:
            self.auto_refresh_count += 1
            self.auto_refresh_timer = self.root.after(int(self.AUTO_REFRESH_INTERVAL * 1000), lambda: self.refresh(silent=True))  # 자동 리프레시는 조용히
        else:
            self.auto_refresh_count = 0
    
    def refresh(self, silent=False):  # silent=True일 때 상태 메시지 표시 안함
        selected_region = self.region_filter.get()
        
        if selected_region == 'ALL':  # ALL일 때는 현재 로드된 모든 리전 재조회
            unique_regions = list(set(inst['region'] for inst in self.instances))
            if not unique_regions:
                return
            for i, region in enumerate(unique_regions):
                is_last = (i == len(unique_regions) - 1)
                self.refresh_specific_region(region, auto_refresh=is_last, silent=silent)  # 마지막 리전만 auto_refresh 활성화
            return
        
        region = self.extract_region_code(selected_region)
        self.refresh_specific_region(region, silent=silent)
    
    def refresh_specific_region(self, region, auto_refresh=True, silent=False):  # 특정 리전만 재조회
        def run():
            try:
                if not silent:  # 자동 리프레시가 아닐 때만 상태 표시
                    self.update_status("Refreshing instances...")
                ec2 = self.create_ec2_client(region)
                resp = ec2.describe_instances()
                
                temp_instances = []
                for r in resp['Reservations']:
                    for i in r['Instances']:
                        temp_instances.append(self.create_instance_dict(i, region))
                
                def check_protection(inst_info):
                    try:
                        ec2 = self.create_ec2_client(inst_info['region'])
                        inst_info['termination_protection'] = self.check_instance_protection(ec2, inst_info['id'], 'disableApiTermination')
                        inst_info['stop_protection'] = self.check_instance_protection(ec2, inst_info['id'], 'disableApiStop')
                    except Exception:
                        pass
                    return inst_info
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(check_protection, inst) for inst in temp_instances]
                    refreshed = [future.result() for future in as_completed(futures)]
                
                for inst in self.instances[:]:
                    if inst['region'] == region:
                        self.instances.remove(inst)
                
                self.instances.extend(refreshed)
                
                self.root.after(0, self.filter_instances)
                if not silent:  # 자동 리프레시가 아닐 때만 상태 표시
                    self.update_status(f"{len(refreshed)} instances refreshed")
                if auto_refresh:  # auto_refresh가 True일 때만 호출
                    self.root.after(0, self.check_and_auto_refresh)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def check_instance_protection(self, ec2, instance_id, attribute):
        try:
            resp = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute=attribute)
            if attribute == 'disableApiTermination':
                return resp.get('DisableApiTermination', {}).get('Value', False)
            elif attribute == 'disableApiStop':
                return resp.get('DisableApiStop', {}).get('Value', False)
        except Exception:
            return False
    
    def refresh_all(self):
        if not hasattr(self, 'regions') or not self.regions:
            return
        
        def run():
            try:
                self.update_status("Loading instances from all regions...")
                temp_instances = []
                found_regions = set()
                seen_ids = set()
                
                for region in self.regions:
                    try:
                        ec2 = self.create_ec2_client(region)
                        resp = ec2.describe_instances()
                        
                        for r in resp['Reservations']:
                            for i in r['Instances']:
                                inst_id = i['InstanceId']
                                if inst_id not in seen_ids:
                                    seen_ids.add(inst_id)
                                    temp_instances.append(self.create_instance_dict(i, region))
                                    found_regions.add(region)
                    except Exception:
                        pass
                
                def check_protection(inst_info):
                    try:
                        ec2 = self.create_ec2_client(inst_info['region'])
                        inst_info['termination_protection'] = self.check_instance_protection(ec2, inst_info['id'], 'disableApiTermination')
                        inst_info['stop_protection'] = self.check_instance_protection(ec2, inst_info['id'], 'disableApiStop')
                    except Exception:
                        pass
                    return inst_info
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(check_protection, inst) for inst in temp_instances]
                    self.instances = [future.result() for future in as_completed(futures)]
                
                region_list = ['ALL'] + sorted([self.get_region_display_name(r) for r in found_regions])  # 콤보박스에 표시용 리전명 사용
                self.root.after(0, lambda: self.region_filter.config(values=region_list))
                self.root.after(0, self.filter_instances)
                self.update_status(f"{len(self.instances)} instances loaded")
                self.root.after(0, self.check_and_auto_refresh)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def filter_instances(self):
        selected_region = self.region_filter.get()
        region_code = self.extract_region_code(selected_region)
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.checked.clear()
        
        filtered = [inst for inst in self.instances if selected_region == 'ALL' or inst['region'] == region_code]  # 필터링
        filtered.sort(key=lambda x: (x['name'].lower() if x['name'] else 'zzz', x['id']))  # 이름순 정렬 (이름 없으면 맨 뒤)
        
        for inst in filtered:
            term_protect_text = '☑' if inst.get('termination_protection') else '☐'
            stop_protect_text = '☑' if inst.get('stop_protection') else '☐'
            region_display = self.get_region_display_name(inst['region'])  # 리전명을 표시용으로 변환
            self.tree.insert('', tk.END, values=('☐', term_protect_text, stop_protect_text, inst['id'], inst['name'], inst['status'], inst['type'], region_display))
    
    def get_selected_instances(self):
        results = []
        for item in self.checked:
            try:
                values = self.tree.item(item)['values']
                region = self.extract_region_code(values[7])
                results.append((values[3], region))  # ID, Region
            except Exception:
                pass
        
        if not results:
            messagebox.showwarning("Warning", "Select instances")
        return results
    
    def group_by_region(self, instances):
        region_map = {}
        for inst_id, region in instances:
            region_map.setdefault(region, []).append(inst_id)
        return region_map
    
    def control_instances(self, action):
        instances = self.get_selected_instances()
        if not instances:
            return
        
        instance_ids = [inst_id for inst_id, _ in instances]
        
        if action == "stop":
            stop_protected_instances = [inst['name'] or inst['id'] for inst in self.instances 
                                        if inst['id'] in instance_ids and inst.get('stop_protection')]
            
            if stop_protected_instances:
                protected_list = '\n'.join(stop_protected_instances[:5])
                if len(stop_protected_instances) > 5:
                    protected_list += f"\n... and {len(stop_protected_instances) - 5} more"
                
                messagebox.showerror(
                    "Stop Protected",
                    f"Cannot stop protected instances:\n\n{protected_list}\n\n"
                    f"Disable stop protection first."
                )
                return
        
        def run():
            try:
                count = len(instances)
                action_text = "Starting" if action == "start" else "Stopping"
                self.update_status(f"{action_text} {count} instance(s)...")
                
                for region, ids in self.group_by_region(instances).items():
                    ec2 = self.create_ec2_client(region)
                    if action == "start":
                        ec2.start_instances(InstanceIds=ids)
                    else:
                        ec2.stop_instances(InstanceIds=ids)
                
                action_past = "started" if action == "start" else "stopped"
                self.root.after(0, lambda: messagebox.showinfo("Success", f"{count} instance(s) {action_past}"))
                self.root.after(0, self.refresh)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def start_instance(self):
        self.control_instances("start")
    
    def stop_instance(self):
        self.control_instances("stop")
    
    def terminate_instance(self):
        instances = self.get_selected_instances()
        if not instances:
            return
        
        instance_ids = [inst_id for inst_id, _ in instances]
        protected_instances = [inst['name'] or inst['id'] for inst in self.instances 
                               if inst['id'] in instance_ids and inst.get('termination_protection')]
        
        if protected_instances:
            protected_list = '\n'.join(protected_instances[:5])
            if len(protected_instances) > 5:
                protected_list += f"\n... and {len(protected_instances) - 5} more"
            
            messagebox.showerror(
                "Termination Protected",
                f"Cannot terminate protected instances:\n\n{protected_list}\n\n"
                f"Disable termination protection first."
            )
            return
        
        count = len(instances)
        if not messagebox.askyesno(
            "⚠️ Confirm Termination",
            f"Are you sure you want to TERMINATE {count} instance(s)?\n\n"
            f"This action CANNOT be undone!\n"
            f"All data on the instance will be permanently deleted.",
            icon='warning'
        ):
            return
        
        def run():
            try:
                self.update_status(f"Terminating {count} instance(s)...")
                
                for region, ids in self.group_by_region(instances).items():
                    ec2 = self.create_ec2_client(region)
                    ec2.terminate_instances(InstanceIds=ids)
                
                self.root.after(0, lambda: messagebox.showinfo("Success", f"{count} instance(s) terminated"))
                self.root.after(0, self.refresh)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
