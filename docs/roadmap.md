# Roadmap posterior a 2.1.0

## 2.2: corrección sobre corpus reales

El siguiente gran salto no debería ser añadir más comandos. Debería ser demostrar
corrección sobre reglas reales:

- corpus públicos grandes de YARA;
- corpus YARA-X;
- reglas válidas e inválidas;
- parse → generate → parse;
- comparación semántica de AST;
- compilación diferencial con libyara y YARA-X;
- métricas públicas por dialecto;
- minimización automática de incompatibilidades.

El objetivo sería poder publicar resultados como:

```text
YARA classic:
  parsed:       99.8 %
  regenerated:  99.7 %
  recompiles:   99.6 %

YARA-X:
  parsed:       ...
  regenerated:  ...
```

Eso generaría mucha más confianza que aumentar simplemente el número bruto de
tests.

## 2.3: AST verdaderamente orientado a refactoring

La diferenciación más fuerte para YARAAST sería:

- source spans completos;
- comentarios y trivia asociados a nodos;
- IDs de nodo estables;
- modificaciones lossless de alto nivel;
- rename de reglas, strings y referencias;
- extracción e inline de expresiones;
- reordenación segura de reglas;
- incremental parsing;
- diff estructural y patches serializables.

`rewrite_lossless()` ya es una buena base, pero el siguiente nivel es que el
usuario pueda expresar:

```python
document.rename_rule("OldName", "NewName")
document.rename_string("$old", "$new")
document.remove_unused_imports()
document.apply()
```

sin perder comentarios ni formato no relacionado.

## Ecosistema y adopción

Después centraría el trabajo en:

- documentación versionada;
- ejemplos pequeños y ejecutables;
- extensión en marketplaces;
- API reference automática;
- tabla comparativa frente a plyara, yaramod y las APIs de YARA-X;
- milestones e issues públicos;
- etiquetas `good first issue`;
- política de soporte para Python y motores YARA;
- calendario de deprecaciones.
