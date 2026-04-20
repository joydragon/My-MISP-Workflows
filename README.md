# My-MISP-Workflows

Estos son una serie de módulos para Workflows que estoy trabajando para la plataforma MISP (https://www.misp-project.org/)

Los Workflows son actividades que pueden automatizar tareas, principalmente de administración, que pueden ayudar a acelerar ciertos procesos "simples" como enriquecimiento de atributos.

Mi objetivo con esto es que podamos transformar esta plataforma de un agente pasivo en el ecosistema de Ciberseguridad a una plataforma activa (SOAR) que integre y distribuya toda la inteligencia que pueda acumular.

## Activar Workflows

Para activar los Worflows, hay que seguir la documentación (https://www.misp-project.org/misp-training/handout/a.12-misp-workflows_handout.pdf)

## Agregar los módulos

Los módulos son archivos .php que están en el repositorio y para agregarlos solo tienes que copiarlos dentro de la carpeta correspondiente (en una instalación por defecto sería: /var/www/MISP/app/Lib/WorkflowModules/action/).

Luego de eso se tienen que definir los módulos que lo usan, generalmente como módulos ad-hoc, y luego utilizarlos como te parezca mejor
