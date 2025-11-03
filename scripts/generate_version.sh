#!/bin/bash
# Jenkins에서 호출하는 버전 생성 스크립트

VERSION=${1:-"1.0.0"}
BUILD_NUMBER=${2:-"0"}
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -I)

cat > src/version.py << PYEOF
"""
버전 정보 (자동 생성됨 - 수정하지 마세요)
Generated: ${BUILD_DATE}
"""
__version__ = "${VERSION}"
__build_number__ = "${BUILD_NUMBER}"
__git_commit__ = "${GIT_COMMIT}"
__build_date__ = "${BUILD_DATE}"

def get_version_string():
    return f"v{__version__} (Build {__build_number__})"

def get_full_version_info():
    return {
        'version': __version__,
        'build': __build_number__,
        'commit': __git_commit__,
        'date': __build_date__
    }
PYEOF

echo "✅ 버전 파일 생성 완료: v${VERSION} build ${BUILD_NUMBER}"
