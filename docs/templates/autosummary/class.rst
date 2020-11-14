{{ objname | escape | underline}}

.. currentmodule:: {{ module }}

.. autoclass:: {{ objname }}
   :members:                                    <-- add at least this line
   :special-members: __add__, __sub__, __neg__, __mul__, __pow__, __rshift__, __invert__, __repr__, __bytes__
   :private-members:
   :show-inheritance:                           <-- plus I want to show inheritance...
   :inherited-members:                          <-- ...and inherited members too
   {% block methods %}
   .. automethod:: __init__

   {% if methods %}
   .. rubric:: {{ _('Methods') }}

   .. autosummary::
   {% for specialitem in ('__add__','__sub__', '__neg__', '__mul__', '__pow__', '__rshift__', '__invert__', '__repr__', '__bytes__') %}
   {% if specialitem in members %}
      ~{{ name }}.{{ specialitem }}
   {% endif %}
   {%- endfor %}
   {% for item in methods %}
      ~{{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block attributes %}
   {% if attributes %}
   .. rubric:: {{ _('Attributes') }}

   .. autosummary::
   {% for item in attributes %}
      ~{{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}
   .. rubric:: {{ _('API description') }}