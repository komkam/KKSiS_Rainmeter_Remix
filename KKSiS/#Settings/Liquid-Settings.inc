;---- Skin Toggle ----

[Background1]
Meter=Shape
Shape=Rectangle 10,35,100,95,3 | Fill Color 50,50,50

[Title1]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=40
Text=#VarToggle#

[Divider1]
Meter=Shape
Shape=Rectangle 12,55,96,2,0 | Fill Color 160,160,160

[Toggle1a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=20
Y=65
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Liquid" "Liquid.ini"]

[Toggle1aText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Panel Skin

[Toggle1b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=-30r
Y=23r
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Liquid" "Liquid.ini"]

[Toggle1bText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Circle Skin


;---- Panel Skin Size ----

[Background2]
Meter=Shape
Shape=Rectangle 120,35,100,95,3 | Fill Color 50,50,50

[Title2]
Meter=String
MeterStyle=SettingsStyle-Text
X=125
Y=40
Text=#VarPanelSize#

[Divider2]
Meter=Shape
Shape=Rectangle 122,55,96,2,0 | Fill Color 160,160,160

[Button2a]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=65
ButtonCommand=[!WriteKeyValue Variables "Panel-LiquidSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"]
[Button2aText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSmall#

[Button2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=21r
ButtonCommand=[!WriteKeyValue Variables "Panel-LiquidSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"]
[Button2bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSquare#

[Button2c]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=21r
ButtonCommand=[!WriteKeyValue Variables "Panel-LiquidSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"]
[Button2cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarBig#


;---- Options ----

[Background3]
Meter=Shape
Shape=Rectangle 230,35,160,95,3 | Fill Color 50,50,50

[Title3]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=40
Text=#VarOptions#

[Divider3]
Meter=Shape
Shape=Rectangle 232,55,156,2,0 | Fill Color 160,160,160

[ButtonDescription31]
Meter=String
MeterStyle=SettingsStyle-Text
Text=Graph / Bar
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#LiquidHideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LiquidHideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#LiquidHideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LiquidHideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#LiquidHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LiquidHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#LiquidHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LiquidHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#LiquidColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LiquidColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#LiquidColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LiquidColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh]


;-- HWiNFO -------------------------------------------------------------------------------- 

[HWiNFO-BG1]
Meter=Shape
Shape=Rectangle 10,140,380,595,3 | Fill Color 50,50,50
Group=HWiNFO

[HWiNFO-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=145
Text=HWiNFO
Group=HWiNFO

[HWiNFO_Status]
Measure=Plugin
Plugin=Process
ProcessName=HWiNFO64.exe
RegExpSubstitute=1
Substitute="-1":"not running","1":"running"
IfCondition=(HWiNFO_Status = 1)
IfTrueAction=[!SetOption HWiNFO_StatusText FontColor "0,255,0"]
IfFalseAction=[!SetOption HWiNFO_StatusText FontColor "255,0,0"]

[HWiNFO_StatusText]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Status
StringAlign=Right
Y=145
X=380
Text=%1

[HWiNFO-Divider1]
Meter=Shape
Shape=Rectangle 12,160,375,2,0 | Fill Color 160,160,160
Group=HWiNFO


[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-Liquid.png
X=135
Y=190
W=125


;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Measure_LeftRL_Name
X=15
Y=165
Text=----- #VarLeftRL# ------#CRLF#Name: Temp Sensor


[Input1d-BG]
Meter=Shape
Shape=Rectangle 15,205,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1d-Field "ExecuteBatch 1-2"]

[Input1e-BG]
Meter=Shape
Shape=Rectangle 15,285,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1e-Field "ExecuteBatch 1-2"]

[Input1d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=206
Text=Max: #Liquid_RLLeft_MaxValue#

[Input1e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=286
Text=Min: #Liquid_RLLeft_MinValue#


[Input1d-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=206
W=115
H=13
FocusDismiss=0
DefaultValue=#Liquid_RLLeft_MaxValue#
Command1=[!SetVariable Liquid_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid_RLLeft_MaxValue [Input1d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]

[Input1e-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=286
W=95
H=13
FocusDismiss=0
DefaultValue=#Liquid_RLLeft_MinValue#
Command1=[!SetVariable Liquid_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid_RLLeft_MinValue [Input1e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=165
Text=------ #VarRightRL# ------#CRLF#Name: All FANs


[Input2d-BG]
Meter=Shape
Shape=Rectangle 280,205,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2d-Field "ExecuteBatch 1-2"]

[Input2e-BG]
Meter=Shape
Shape=Rectangle 280,285,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2e-Field "ExecuteBatch 1-2"]

[Input2d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=206
Text=Max: #Liquid_RLRight_MaxValue#

[Input2e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=286
Text=Min: #Liquid_RLRight_MinValue#


[Input2d-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=206
W=95
H=13
FocusDismiss=0
DefaultValue=#Liquid_RLRight_MaxValue#
Command1=[!SetVariable Liquid_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid_RLRight_MaxValue [Input2d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]

[Input2e-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=286
W=95
H=13
FocusDismiss=0
DefaultValue=#Liquid_RLRight_MinValue#
Command1=[!SetVariable Liquid_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid_RLRight_MinValue [Input2e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=316
Text=Liquid Name:

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,315,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=316
Text=#LiquidName#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=316
W=95
H=13
FocusDismiss=0
DefaultValue=#LiquidName#
Command1=[!SetVariable LiquidName "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables LiquidName [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


;---- HWiNFO Sensors

[HWiNFO-Divider2]
Meter=Shape
Shape=Rectangle 12,335,375,2,0 | Fill Color 160,160,160
Group=HWiNFO


[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=360
Y=340
Text="Sensor ID        Instance         Entry ID"

;-- Configuration Input -------------------------------------------------------------------------------- 

[Input4-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=366
Text="Temperature Sensor"

[Input4a-BG]
Meter=Shape
Shape=Rectangle 160,365,80,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input4a-Field "ExecuteBatch 1-2"]
[Input4b-BG]
Meter=Shape
Shape=Rectangle 250,365,40,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]
[Input4c-BG]
Meter=Shape
Shape=Rectangle 300,365,80,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input4c-Field "ExecuteBatch 1-2"]

[Input4a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=366
Text=#Liquid-Sensor-Temp_ID#

[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Liquid-Sensor-Temp_Instance#

[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Liquid-Sensor-Temp_EntryID#


[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=366
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-Sensor-Temp_ID#
Command1=[!SetVariable Liquid-Sensor-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-Sensor-Temp_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=366
W=35
H=13
FocusDismiss=0
DefaultValue=#Liquid-Sensor-Temp_Instance#
Command1=[!SetVariable Liquid-Sensor-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-Sensor-Temp_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=366
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-Sensor-Temp_EntryID#
Command1=[!SetVariable Liquid-Sensor-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-Sensor-Temp_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=386
Text="Pump Speed"

[Input5a-BG]
Meter=Shape
Shape=Rectangle 160,385,80,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input5a-Field "ExecuteBatch 1-2"]
[Input5b-BG]
Meter=Shape
Shape=Rectangle 250,385,40,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input5b-Field "ExecuteBatch 1-2"]
[Input5c-BG]
Meter=Shape
Shape=Rectangle 300,385,80,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input5c-Field "ExecuteBatch 1-2"]

[Input5a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=386
Text=#Liquid-Sensor-Pump_ID#

[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Liquid-Sensor-Pump_Instance#

[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Liquid-Sensor-Pump_EntryID#


[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=386
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-Sensor-Pump_ID#
Command1=[!SetVariable Liquid-Sensor-Pump_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-Sensor-Pump_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=386
W=35
H=13
FocusDismiss=0
DefaultValue=#Liquid-Sensor-Pump_Instance#
Command1=[!SetVariable Liquid-Sensor-Pump_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-Sensor-Pump_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=386
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-Sensor-Pump_EntryID#
Command1=[!SetVariable Liquid-Sensor-Pump_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-Sensor-Pump_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=406
Text="Radiator FAN1"


[Input6a-BG]
Meter=Shape
Shape=Rectangle 160,405,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input6a-Field "ExecuteBatch 1-2"]
[Input6b-BG]
Meter=Shape
Shape=Rectangle 250,405,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input6b-Field "ExecuteBatch 1-2"]
[Input6c-BG]
Meter=Shape
Shape=Rectangle 300,405,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input6c-Field "ExecuteBatch 1-2"]

[Input6a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=406
Text=#Liquid-FAN1_ID#

[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Liquid-FAN1_Instance#

[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Liquid-FAN1_EntryID#


[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=406
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN1_ID#
Command1=[!SetVariable Liquid-FAN1_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN1_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=406
W=35
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN1_Instance#
Command1=[!SetVariable Liquid-FAN1_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN1_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=406
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN1_EntryID#
Command1=[!SetVariable Liquid-FAN1_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN1_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=426
Text="Radiator FAN2"

[Input7a-BG]
Meter=Shape
Shape=Rectangle 160,425,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input7a-Field "ExecuteBatch 1-2"]
[Input7b-BG]
Meter=Shape
Shape=Rectangle 250,425,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input7b-Field "ExecuteBatch 1-2"]
[Input7c-BG]
Meter=Shape
Shape=Rectangle 300,425,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input7c-Field "ExecuteBatch 1-2"]

[Input7a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=426
Text=#Liquid-FAN2_ID#

[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Liquid-FAN2_Instance#

[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Liquid-FAN2_EntryID#


[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=426
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN2_ID#
Command1=[!SetVariable Liquid-FAN2_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN2_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=426
W=35
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN2_Instance#
Command1=[!SetVariable Liquid-FAN2_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN2_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=426
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN2_EntryID#
Command1=[!SetVariable Liquid-FAN2_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN2_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


[Input8-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=446
Text="Radiator FAN3"

[Input8a-BG]
Meter=Shape
Shape=Rectangle 160,445,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input8a-Field "ExecuteBatch 1-2"]
[Input8b-BG]
Meter=Shape
Shape=Rectangle 250,445,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input8b-Field "ExecuteBatch 1-2"]
[Input8c-BG]
Meter=Shape
Shape=Rectangle 300,445,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input8c-Field "ExecuteBatch 1-2"]

[Input8a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=446
Text=#Liquid-FAN3_ID#

[Input8b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Liquid-FAN3_Instance#

[Input8c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Liquid-FAN3_EntryID#


[Input8a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=446
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN3_ID#
Command1=[!SetVariable Liquid-FAN3_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN3_ID [Input8a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input8b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=446
W=35
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN3_Instance#
Command1=[!SetVariable Liquid-FAN3_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN3_Instance [Input8b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]
[Input8c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=446
W=75
H=13
FocusDismiss=0
DefaultValue=#Liquid-FAN3_EntryID#
Command1=[!SetVariable Liquid-FAN3_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Liquid-FAN3_EntryID [Input8c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Liquid"][!Refresh "#ROOTCONFIG#\Panels\Liquid"][!Update]


[InfoText1]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=470
Text=Info:

[InfoText2]
Meter=String
MeterStyle=SettingsStyle-Text
X=50
Y=470
Text=#VarLiquidInfo#


;-- HWiNFO SM Viewer ---------------------------------------------------------------------------------- 

[HWiNFOSMV]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=700
LeftMouseUpAction=["#@#Tools\HWiNFOSharedMemoryViewer.exe]

[HWiNFOSMVText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Open HWiNFO Shared Memory Viewer"

