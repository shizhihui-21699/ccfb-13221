"""Smugglelab: a local HTTP request-smuggling range with a detection engine.

Top-level pieces:

* ``httpdialect``  -- the parser and the flags that define a hop's behaviour;
* ``dialects``     -- named presets modelled on real proxies and origins;
* ``lab``          -- a front-end proxy and a back-end origin running live;
* ``templates``    -- the catalogue of ambiguous request constructions;
* ``engine``       -- the black-box, cross-connection detection oracle;
* ``instrumented`` -- per-hop framing differential (covers every template);
* ``range``        -- scenarios and the matrix runner;
* ``report``       -- the self-contained HTML report;
* ``samples``      -- reproducible request rendering.
"""

__version__ = "0.1.0"
