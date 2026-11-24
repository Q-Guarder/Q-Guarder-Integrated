# 발표 · 제출 자료

| 자료 | 파일 |
|---|---|
| 최종 발표자료 | `최종발표자료.pdf` |
| 포스터 | `포스터.pdf` |
| 학술대회 논문 | `학술대회논문.pdf` |

## 시연용 QR 코드 (`demo_qr/`)

| 판정 | 파일 | QR에 담긴 URL | 측정 점수 |
|---|---|---|---|
| 안전 | `qguard_1_safe.png` | `https://www.google.com` | 29점 (VT 0/93) |
| 주의 | `qguard_2_suspicious.png` | `https://parking-fine-payment.example/pay` | 62점 (VT 미등재, ML 단독) |
| 위험 | `qguard_3_blocked.png` | `https://naver-security-check.test/login` | 79점 (VT 미등재, ML 단독) |

- `demo_qr.html`: 세 장을 한 페이지에 모은 인쇄용 파일 (이미지 내장, 인터넷 없이 열림)
- 주의·위험 URL은 예약 도메인(`.example`, `.test`)이라 실제로 접속되는 사이트가 없습니다. 관람객이 자기 휴대폰으로 찍어도 안전합니다.
- 점수는 로컬 서버로 측정한 값입니다. 안전 판정은 VirusTotal 조회 결과에 따라 달라질 수 있습니다(VT 키가 없으면 정상 URL도 위험으로 나옵니다).
- 에뮬레이터에서는 Extended controls → Camera → Virtual scene images → Wall에 PNG를 지정하면 가상 카메라로 스캔할 수 있습니다.
