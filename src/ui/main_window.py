"""
메인 윈도우 UI
기존 aws_controller.py를 리팩토링하여 UI 로직만 유지
"""
import tkinter as tk
from tkinter import messagebox, ttk
import threading
from typing import List, Optional

from src.core.ec2_manager import EC2Manager, EC2Instance
from src.core.config_manager import ConfigManager
from src.version import get_version_string


class MainWindow:
    """메인 윈도우 (UI 로직만)"""
    
    WINDOW_WIDTH = 1200
    WINDOW_HEIGHT = 550
    AUTO_REFRESH_INTERVAL = 3.0
    AUTO_REFRESH_MAX_COUNT = 30
    TRANSITIONING_STATES = ['pending', 'stopping', 'shutting-down', 'terminating']
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"EC2 Controller - {get_version_string()}")
        self.root.geometry(f"{self.WINDOW_WIDTH}x{self.WINDOW_HEIGHT}")
        self.root.resizable(True, True)
        self.root.minsize(1000, 450)
        
        # 핵심 객체들
        self.ec2_manager: Optional[EC2Manager] = None
        self.config_manager = ConfigManager()
        
        # UI 상태
        self.instances: List[EC2Instance] = []
        self.checked = set()
        self.auto_refresh_timer = None
        self.auto_refresh_count = 0
        
        # UI 구성
        self.setup_ui()
        self.load_saved_credentials()
    
    def setup_ui(self):
        """UI 구성"""
        self.status = tk.Label(self.root, text="Login required (Click checkbox for select)")
        self.status.pack(side=tk.BOTTOM, pady=5)
        
        self.setup_control_buttons()
        self.setup_login_ui()
        self.setup_instance_list_ui()
    
    def setup_control_buttons(self):
        """컨트롤 버튼 구성"""
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
    
    def setup_login_ui(self):
        """로그인 UI 구성"""
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
        """인스턴스 리스트 UI 구성"""
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
        
        tree_frame = tk.Frame(list_ui)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tree = ttk.Treeview(
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
    
    def on_tree_click(self, event):
        """트리 클릭 이벤트 처리"""
        if self.tree.identify_region(event.x, event.y) != 'cell':
            return
        
        column = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)
        if not item:
            return
        
        values = list(self.tree.item(item)['values'])
        
        if column == '#1':  # Select 체크박스
            if item in self.checked:
                self.checked.remove(item)
                values[0] = '☐'
            else:
                self.checked.add(item)
                values[0] = '☑'
            self.tree.item(item, values=values)
        
        elif column in ('#2', '#3'):  # Protection 토글
            instance_id = values[3]
            region = EC2Manager.extract_region_code(values[7])
            protection_type = 'termination' if column == '#2' else 'stop'
            index = 1 if column == '#2' else 2
            current_state = values[index] == '☑'
            self.toggle_protection(instance_id, region, protection_type, not current_state)
    
    def toggle_protection(self, instance_id, region, protection_type, enable):
        """Protection 토글"""
        def run():
            try:
                if protection_type == 'termination':
                    self.ec2_manager.set_termination_protection(instance_id, region, enable)
                    protection_name = 'Termination Protection'
                else:
                    self.ec2_manager.set_stop_protection(instance_id, region, enable)
                    protection_name = 'Stop Protection'
                
                # 인스턴스 정보 업데이트
                for inst in self.instances:
                    if inst.id == instance_id:
                        if protection_type == 'termination':
                            inst.termination_protection = enable
                        else:
                            inst.stop_protection = enable
                        break
                
                self.root.after(0, lambda: self.refresh_specific_region(region))
                action = "enabled" if enable else "disabled"
                self.update_status(f"{protection_name} {action} for {instance_id}")
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def update_status(self, text):
        """상태 바 업데이트"""
        self.root.after(0, lambda: self.status.config(text=text))
    
    def load_saved_credentials(self):
        """저장된 자격증명 로드"""
        creds = self.config_manager.load_credentials()
        if creds:
            access_key, secret_key = creds
            self.key_input.insert(0, access_key)
            self.secret_input.insert(0, secret_key)
    
    def login(self):
        """로그인 처리"""
        key = self.key_input.get().strip()
        secret = self.secret_input.get().strip()
        
        if not key or not secret:
            messagebox.showwarning("Warning", "Enter all credentials")
            return
        
        def run():
            try:
                self.update_status("Logging in...")
                
                # EC2Manager 생성
                self.ec2_manager = EC2Manager(key, secret)
                
                # 리전 목록 로드 (연결 테스트)
                self.ec2_manager.get_available_regions()
                
                # 자격증명 저장
                self.config_manager.save_credentials(key, secret)
                
                # UI 업데이트
                self.root.after(0, self.on_login_success)
                
                # 인스턴스 조회
                self.root.after(0, self.refresh_all)
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Login Failed", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def on_login_success(self):
        """로그인 성공 시 UI 업데이트"""
        for btn in self.control_buttons:
            btn.config(state=tk.NORMAL)
        
        self.login_btn.config(state=tk.DISABLED)
        self.key_input.config(state=tk.DISABLED)
        self.secret_input.config(state=tk.DISABLED)
    
    def refresh_all(self):
        """모든 리전의 인스턴스 조회"""
        def run():
            try:
                self.update_status("Loading instances from all regions...")
                
                # EC2Manager에 위임
                instances = self.ec2_manager.get_all_instances()
                
                self.instances = instances
                
                # 리전 필터 업데이트
                found_regions = set(inst.region for inst in instances)
                region_list = ['ALL'] + sorted([
                    EC2Manager.get_region_display_name(r) for r in found_regions
                ])
                self.root.after(0, lambda: self.region_filter.config(values=region_list))
                
                # UI 업데이트
                self.root.after(0, self.filter_instances)
                self.update_status(f"{len(instances)} instances loaded")
                self.root.after(0, self.check_and_auto_refresh)
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def refresh(self, silent=False):
        """현재 선택된 리전 새로고침"""
        selected_region = self.region_filter.get()
        
        if selected_region == 'ALL':
            unique_regions = list(set(inst.region for inst in self.instances))
            if not unique_regions:
                return
            for i, region in enumerate(unique_regions):
                is_last = (i == len(unique_regions) - 1)
                self.refresh_specific_region(region, auto_refresh=is_last, silent=silent)
            return
        
        region = EC2Manager.extract_region_code(selected_region)
        self.refresh_specific_region(region, silent=silent)
    
    def refresh_specific_region(self, region, auto_refresh=True, silent=False):
        """특정 리전 새로고침"""
        def run():
            try:
                if not silent:
                    self.update_status("Refreshing instances...")
                
                # 해당 리전 인스턴스 조회
                refreshed = self.ec2_manager.get_instances_in_region(region)
                
                # 기존 인스턴스 중 해당 리전 제거
                self.instances = [inst for inst in self.instances if inst.region != region]
                
                # 새로운 인스턴스 추가
                self.instances.extend(refreshed)
                
                self.root.after(0, self.filter_instances)
                if not silent:
                    self.update_status(f"{len(refreshed)} instances refreshed")
                if auto_refresh:
                    self.root.after(0, self.check_and_auto_refresh)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def check_and_auto_refresh(self):
        """자동 새로고침 체크"""
        if self.auto_refresh_timer:
            self.root.after_cancel(self.auto_refresh_timer)
            self.auto_refresh_timer = None
        
        has_transitioning = any(
            inst.status in self.TRANSITIONING_STATES for inst in self.instances
        )
        
        if has_transitioning and self.auto_refresh_count < self.AUTO_REFRESH_MAX_COUNT:
            self.auto_refresh_count += 1
            self.auto_refresh_timer = self.root.after(
                int(self.AUTO_REFRESH_INTERVAL * 1000), 
                lambda: self.refresh(silent=True)
            )
        else:
            self.auto_refresh_count = 0
    
    def filter_instances(self):
        """인스턴스 필터링 및 표시"""
        selected_region = self.region_filter.get()
        region_code = EC2Manager.extract_region_code(selected_region)
        
        # 기존 항목 삭제
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.checked.clear()
        
        # 필터링
        filtered = [
            inst for inst in self.instances 
            if selected_region == 'ALL' or inst.region == region_code
        ]
        
        # 이름순 정렬
        filtered.sort(key=lambda x: (x.name.lower() if x.name else 'zzz', x.id))
        
        # 트리에 추가
        for inst in filtered:
            term_protect_text = '☑' if inst.termination_protection else '☐'
            stop_protect_text = '☑' if inst.stop_protection else '☐'
            region_display = EC2Manager.get_region_display_name(inst.region)
            
            self.tree.insert('', tk.END, values=(
                '☐', 
                term_protect_text, 
                stop_protect_text, 
                inst.id, 
                inst.name, 
                inst.status, 
                inst.type, 
                region_display
            ))
    
    def get_selected_instances(self):
        """선택된 인스턴스 가져오기"""
        results = []
        for item in self.checked:
            try:
                values = self.tree.item(item)['values']
                region = EC2Manager.extract_region_code(values[7])
                results.append((values[3], region))  # ID, Region
            except Exception:
                pass
        
        if not results:
            messagebox.showwarning("Warning", "Select instances")
        return results
    
    def group_by_region(self, instances):
        """인스턴스를 리전별로 그룹화"""
        region_map = {}
        for inst_id, region in instances:
            region_map.setdefault(region, []).append(inst_id)
        return region_map
    
    def control_instances(self, action):
        """인스턴스 제어 (시작/중지)"""
        instances = self.get_selected_instances()
        if not instances:
            return
        
        instance_ids = [inst_id for inst_id, _ in instances]
        
        # Stop protection 체크
        if action == "stop":
            stop_protected = [
                inst.name or inst.id for inst in self.instances 
                if inst.id in instance_ids and inst.stop_protection
            ]
            
            if stop_protected:
                protected_list = '\n'.join(stop_protected[:5])
                if len(stop_protected) > 5:
                    protected_list += f"\n... and {len(stop_protected) - 5} more"
                
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
                    if action == "start":
                        self.ec2_manager.start_instances(ids, region)
                    else:
                        self.ec2_manager.stop_instances(ids, region)
                
                action_past = "started" if action == "start" else "stopped"
                self.root.after(0, lambda: messagebox.showinfo("Success", f"{count} instance(s) {action_past}"))
                self.root.after(0, self.refresh)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
    
    def start_instance(self):
        """인스턴스 시작"""
        self.control_instances("start")
    
    def stop_instance(self):
        """인스턴스 중지"""
        self.control_instances("stop")
    
    def terminate_instance(self):
        """인스턴스 삭제"""
        instances = self.get_selected_instances()
        if not instances:
            return
        
        instance_ids = [inst_id for inst_id, _ in instances]
        
        # Termination protection 체크
        protected = [
            inst.name or inst.id for inst in self.instances 
            if inst.id in instance_ids and inst.termination_protection
        ]
        
        if protected:
            protected_list = '\n'.join(protected[:5])
            if len(protected) > 5:
                protected_list += f"\n... and {len(protected) - 5} more"
            
            messagebox.showerror(
                "Termination Protected",
                f"Cannot terminate protected instances:\n\n{protected_list}\n\n"
                f"Disable termination protection first."
            )
            return
        
        count = len(instances)
        if not messagebox.askyesno(
            "Confirm Termination",
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
                    self.ec2_manager.terminate_instances(ids, region)
                
                self.root.after(0, lambda: messagebox.showinfo("Success", f"{count} instance(s) terminated"))
                self.root.after(0, self.refresh)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=run, daemon=True).start()
