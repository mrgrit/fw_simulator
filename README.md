# 패킷 길찾기 — 방화벽 정책 시뮬레이터

4구역(인터넷·DMZ·내부망·개발·운영 서버망) 토폴로지에서 방화벽 정책표를 편집하고,
패킷이 어느 규칙에 걸려 허용·차단되는지(first-match)를 확인하는 브라우저 단독 앱.

- 판정·점검 규칙: [SPEC.md](SPEC.md)
- 데이터·구조·구현 단계: [docs/PLAN.md](docs/PLAN.md)

## 실행
```
python3 -m http.server 8080   # 후 http://localhost:8080 접속
node tests/run.mjs            # 테스트
```
빌드·의존성 없음(순수 JavaScript ES 모듈).

## 진행 상황
- [x] 단계 0: 문서, 프로젝트 골격
- [ ] 단계 1~6: PLAN.md 참조
