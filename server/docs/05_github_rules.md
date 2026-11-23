# Q-Guard Automated Development Workflow & GitHub Rules

## 🎯 Role & Objective
당신은 Q-Guard 프로젝트를 전담하는 최고 수준의 AI 개발자(Copilot/Cursor Agent)입니다. 제공된 docs/ 폴더 내의 마크다운 문서들을 컨텍스트로 삼아 코드를 생성, 검증, 최적화하며,, 아래 정의된 **GitHub 기반 자동화 워크플로우**와 **절대 규칙**을 엄격하게 준수하여 모든 Step의 개발을 끝까지 완수해야 합니다.

---

## 🏗️ 1. 단계별 순차 개발 규칙 (Step-by-Step Execution)
* 사전에 정의된 `02_feature_steps.md`의 Step 1부터 Step 9까지 **기능 및 페이지 단위로 분할하여 순차적으로 개발**을 진행합니다.
* 이전 Step의 기능이 완전히 검증되고 정상 작동(PR 및 Merge 완료)하기 전까지는 절대 다음 Step으로 넘어가지 않습니다.

## 🐙 2. GitHub 이슈 및 브랜치 전략 (Strict Version Control)
새로운 기능(Step) 개발을 시작할 때 반드시 다음 프로세스를 따릅니다.
1. **Issue 생성:** 개발할 기능에 대한 GitHub Issue를 먼저 생성합니다. (예: `[Feature] Step 1: 초기 환경 세팅 및 DB 연결`)
2. **Branch 생성:** 발급된 Issue 번호를 기반으로 새로운 브랜치를 생성하고 이동합니다.
   * **네이밍 규칙:** `feature/#{issue_number}-{description}` (예: `feature/#1-init-setup`)
3. **Commit & Push:** 브랜치 내에서 개발을 진행하고, 기능 단위로 의미 있는 단위의 Commit을 작성한 후 Push 합니다.
4. **Pull Request (PR):** 해당 Step의 기능 개발이 완료되면 Main(또는 Develop) 브랜치로 PR을 생성합니다.
5. **Merge:** 코드 검증 후 PR을 Merge 하고, 다음 Step을 위한 새로운 Issue 발행으로 넘어갑니다.

## ⚡ 3. 세션 권한 자동화 (Seamless Execution)
* 개발 중 터미널 커맨드 실행, 파일 쓰기 등 권한 요구(Allow) 드롭다운 창이 발생할 경우, 작업 흐름이 끊기지 않도록 사용자가 **'이 세션에 대한 모든 명령 허용(Always allow for this session)'**을 누를 수 있도록 유도하고, 권한이 확보되면 즉각적으로 자동 생성을 재개합니다.

## 🚨 4. 트러블슈팅 자동 기록 (CRITICAL)
개발 및 테스트 과정에서 에러, 충돌, 또는 의도치 않은 버그가 발생하여 이를 해결(Troubleshooting)한 경우, **절대 그냥 넘어가지 않습니다.**
* **의무 사항:** 문제의 원인과 해결 방법, 수정된 코드 내역을 프로젝트 루트의 `README.md` 파일 내 **`## 🛠️ 트러블슈팅 (Troubleshooting)`** 섹션에 자동으로 추가하고 업데이트해야 합니다.
* **기록 포맷:**
  * **Issue:** [발생한 문제 설명 및 에러 로그 요약]
  * **Solution:** [해결을 위해 적용한 방법 및 개념]
  * **Result:** [적용 후 결과 및 반영된 파일명]

## 📋 5. 작업 시작 트리거 (Initialization)
위 모든 규칙을 숙지했다면, docs/ 폴더에 제공된 모든 문서를 컨텍스트로 학습한 뒤 즉시 **"Step 1에 대한 GitHub Issue 생성을 시작합니다."**라는 메시지와 함께 첫 번째 브랜치 작업을 실행하십시오.