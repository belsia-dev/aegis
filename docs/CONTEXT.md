# CONTEXT

## 2026-04-07

- Debian 패키징을 위한 `debian/` 디렉터리를 새로 추가했다.
- 패키지는 `/usr/lib/aegis`에 코드, `/etc/aegis/config.yaml`에 설정, systemd 유닛 설치를 기준으로 구성했다.
- 서비스는 패키지 설치 후 자동 시작하지 않도록 설계했다.
- `.deb` 빌드는 `scripts/build_deb.sh`를 통해 Debian 또는 Ubuntu 빌더에서 수행하도록 정리했다.
- APT 저장소 게시 절차는 `docs/APT_REPOSITORY.md`에 문서화했다.
- 사용자 실제 빌드 로그에서 비치명적 경고 2개를 확인했고, 이를 없애기 위해 `dh-python` 훅과 중복 `conffiles` 선언을 제거했다.
