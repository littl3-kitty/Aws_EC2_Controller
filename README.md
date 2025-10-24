# AWS EC2 Instance Controller

AWS EC2 인스턴스 관리용 프로그램

## 1. 기능

- 여러 리전의 EC2 인스턴스 조회
- 인스턴스 시작/중지
- 자격증명 암호화 저장

## 2. 사용 방법

### a. 설치방법 (사용 버전 : Python 3.14.0)
       : cmd 또는 powershell에서 아래 명령 실행
```bash
pip install -r requirements.txt
python aws_controller.py
```

### b. 실행 파일 빌드 (Windows)

```bash
build.bat
```

빌드된 파일은 `./dist/aws_instance_control.exe`에 생성됩니다.

### c. 사용법

- AWS Access Key와 Secret Key 입력 (`~/.aws_ctrl_cfg`에 암호화 저장)
- Login 클릭 (모든 리전 인스턴스 조회)
- Refresh : 현재 불러온 리전/인스턴스만 조회
- All Refresh : 모든 리전의 인스턴스 조회
- Start : 인스턴스 시작
- Stop : 인스턴스 중지

## 3. 필요한 AWS 최소권한

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeRegions",
    "ec2:StartInstances",
    "ec2:StopInstances"
  ],
  "Resource": "*"
}
```

## 4. 라이선스
라이선스 파일 참조
