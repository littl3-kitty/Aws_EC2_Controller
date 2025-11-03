"""
버전 정보 (자동 생성됨 - 수정하지 마세요)
Generated: 2025-11-03
"""
__version__ = "1.0.0"
__build_number__ = "1"
__git_commit__ = "6a2ae31"
__build_date__ = "2025-11-03"

def get_version_string():
    return f"v{__version__} (Build {__build_number__})"

def get_full_version_info():
    return {
        'version': __version__,
        'build': __build_number__,
        'commit': __git_commit__,
        'date': __build_date__
    }
