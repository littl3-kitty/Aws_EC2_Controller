# AWS EC2 Instance Controller
여러 AWS 리전의 EC2 인스턴스를 한 번에 관리할 수 있는 Windows GUI 관리 도구

## 1. 기능
- 여러 리전의 EC2 인스턴스 조회
- 인스턴스 시작/중지/삭제
- 자격증명 암호화 저장

## 2. 사용 방법


### a. 사전 준비
1) Python 3.14.0 이상 설치
2) pip가 정상 작동하는지 확인 (`pip --version`)

3) 보안 주의사항:
  - AWS Access Key는 제한된 권한(아래 3번 참고)만 부여하세요
  - 자격증명은 로컬에 암호화되어 저장됩니다 (`~/.aws_ctrl_cfg`)
  - 해당 파일을 다른 사람과 공유하지 마세요

### b. EXE 파일 빌드(windows)
```bash
build.bat
```
- 첫 실행 시 필요한 패키지 자동 설치 (boto3, pyinstaller, cryptography)
- 빌드 완료 후 `./dist/aws_instance_control.exe` 생성

### c. 사용법

- AWS Access Key와 Secret Key 입력 (`~/.aws_ctrl_cfg`에 암호화 저장)
- Login 클릭 (모든 리전 인스턴스 조회)
- Refresh : 현재 불러온 리전/인스턴스만 조회
- All Refresh : 모든 리전의 인스턴스 조회
- Start : 인스턴스 시작
- Stop : 인스턴스 중지
- Terminate : 인스턴스 삭제 (복구 불가!)

## 3. 필요한 AWS 최소권한

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeRegions",
    "ec2:DescribeInstanceAttribute",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances"
  ],
  "Resource": "*"
}
```

## 4. 라이선스
라이선스 파일 참조
