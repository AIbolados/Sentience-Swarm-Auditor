"""Guardrail de autorizacion para el motor DAST activo (Fase 4).

A diferencia del motor SAST (solo lee codigo fuente), el DAST ejecuta
trafico real contra un target: puede tener efectos sobre un sistema en
vivo (carga, falsos disparos de alertas, en el peor caso degradar el
servicio si es demasiado agresivo). Por eso nunca corre sin que quien lo
invoca confirme explicitamente que el target es propio o esta
autorizado, y nunca contra produccion sin una confirmacion adicional y
throttling mas conservador.

Este modulo no ejecuta ningun escaneo: solo decide si esta autorizado y
que limites de agresividad aplicar.
"""

from dataclasses import dataclass
from enum import Enum


class TargetEnvironment(str, Enum):
    LOCAL_STAGING = "local_staging"
    PRODUCTION = "production"


class TargetNotAuthorizedError(PermissionError):
    pass


@dataclass(frozen=True)
class ScanLimits:
    rate_limit: int  # requests/segundo permitidos a nuclei
    concurrency: int  # templates concurrentes
    max_duration_seconds: int


LIMITS_BY_ENVIRONMENT: dict[TargetEnvironment, ScanLimits] = {
    # local/staging: sin usuarios reales detras, se puede ir mas rapido.
    TargetEnvironment.LOCAL_STAGING: ScanLimits(
        rate_limit=150, concurrency=25, max_duration_seconds=600
    ),
    # produccion: conservador por defecto. Un escaneo agresivo contra un
    # servicio con trafico real puede degradarlo; el objetivo es detectar
    # vulnerabilidades, no generar una carga que parezca un DoS.
    TargetEnvironment.PRODUCTION: ScanLimits(
        rate_limit=10, concurrency=2, max_duration_seconds=300
    ),
}


@dataclass(frozen=True)
class ScanAuthorization:
    target: str
    environment: TargetEnvironment
    confirm_own_target: bool
    confirm_production_risk: bool = False

    def validate(self) -> None:
        if not self.confirm_own_target:
            raise TargetNotAuthorizedError(
                f"Escaneo activo rechazado para {self.target!r}: falta "
                "confirm_own_target=True. El DAST activo ejecuta peticiones "
                "reales contra el target; solo debe usarse contra sistemas "
                "propios o con autorizacion explicita y por escrito del dueño. "
                "Nunca contra sistemas de terceros sin ese consentimiento."
            )
        if self.environment == TargetEnvironment.PRODUCTION and not self.confirm_production_risk:
            raise TargetNotAuthorizedError(
                f"Escaneo activo contra produccion rechazado para {self.target!r}: "
                "falta ademas confirm_production_risk=True. Un escaneo activo "
                "puede degradar el servicio (carga extra, falsos positivos en "
                "monitoreo); confirma que corres esto en una ventana aceptada "
                "por tu equipo, no contra trafico de usuarios reales sin aviso."
            )

    @property
    def limits(self) -> ScanLimits:
        return LIMITS_BY_ENVIRONMENT[self.environment]
