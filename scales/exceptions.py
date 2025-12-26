class AppError(Exception):
    """Базовая ошибка проекта (общий предок)."""

class ProtocolError(AppError):
    """Нарушение протокола/формата данных."""

class DeviceError(AppError):
    """Устройство вернуло ошибку (код/статус)."""