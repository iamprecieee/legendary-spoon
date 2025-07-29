from .services import DataSanitizer


async def get_data_sanitizer() -> DataSanitizer:
    return DataSanitizer()
