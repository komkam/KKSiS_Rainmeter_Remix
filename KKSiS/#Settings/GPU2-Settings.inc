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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\GPU2" "GPU2.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\GPU2" "GPU2.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-GPU2Size" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-GPU2Size" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-GPU2Size" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"]
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
ButtonImage=#@#Images\Buttons\Hide#GPU2HideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPU2HideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#GPU2HideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPU2HideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#GPU2HideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPU2HideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#GPU2HideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPU2HideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#GPU2ColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPU2ColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#GPU2ColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPU2ColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]


;-- Technology -------------------------------------------------------------------------------- 

[BG3]
Meter=Shape
Shape=Rectangle 10,140,380,65,3 | Fill Color 50,50,50

[T3Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=145
Text=#VarTechnology#

[T3Divider]
Meter=Shape
Shape=Rectangle 12,160,375,2,0 | Fill Color 160,160,160

[Technology1Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=20
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "GPU2Format" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2Format2" "" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2HideHWiNFO" "0" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2HideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]

[Technology1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=6r
Text=HWiNFO 1

[Technology2Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=80r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "GPU2Format" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2Format2" "2" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2HideHWiNFO" "0" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2HideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]

[Technology2Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=6r
Text=HWiNFO 2

[Technology3Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=80r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "GPU2Format" "MSIAB" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2Format2" "" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2HideHWiNFO" "1" "#@#Variables.inc"][!WriteKeyValue Variables "GPU2HideMSIAB" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh]

[Technology3Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=6r
Text=MSI Afterburner


;-- HWiNFO -------------------------------------------------------------------------------- 

[HWiNFO-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Group=HWiNFO
Hidden=#GPU2HideHWiNFO#

[HWiNFO-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=HWiNFO
Group=HWiNFO
Hidden=#GPU2HideHWiNFO#

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
Y=220
X=380
Text=%1
Hidden=#GPU2HideHWiNFO#

[HWiNFO-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#GPU2HideHWiNFO#

[HWiNFO_Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU2-LeftRL_Id#
HWiNFOSensorInstance=#GPU2-LeftRL_Instance#
HWiNFOEntryId		=#GPU2-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#GPU2HideHWiNFO#


[HWiNFO_Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU2-RightRL_Id#
HWiNFOSensorInstance=#GPU2-RightRL_Instance#
HWiNFOEntryId		=#GPU2-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#GPU2HideHWiNFO#

[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-GPU.png
X=135
Y=265
W=125
Hidden=#GPU2HideHWiNFO#


;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Measure_LeftRL_Name
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: %1
Hidden=#GPU2HideHWiNFO#

[Input1a-BG]
Meter=Shape
Shape=Rectangle 15,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1a-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input1b-BG]
Meter=Shape
Shape=Rectangle 15,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1b-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input1c-BG]
Meter=Shape
Shape=Rectangle 15,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1c-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input1d-BG]
Meter=Shape
Shape=Rectangle 15,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1d-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input1e-BG]
Meter=Shape
Shape=Rectangle 15,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1e-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input1a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=281
Text=SensorID: #GPU2-LeftRL_Id#
Hidden=#GPU2HideHWiNFO#
[Input1b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=301
Text=Instance: #GPU2-LeftRL_Instance#
Hidden=#GPU2HideHWiNFO#
[Input1c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=321
Text=EntryID: #GPU2-LeftRL_EntryID#
Hidden=#GPU2HideHWiNFO#
[Input1d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=341
Text=Max: #GPU2_RLLeft_MaxValue#
Hidden=#GPU2HideHWiNFO#
[Input1e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=361
Text=Min: #GPU2_RLLeft_MinValue#
Hidden=#GPU2HideHWiNFO#

[Input1a-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#GPU2-LeftRL_Id#
Command1=[!SetVariable GPU2-LeftRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-LeftRL_Id [Input1a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input1b-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU2-LeftRL_Instance#
Command1=[!SetVariable GPU2-LeftRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-LeftRL_Instance [Input1b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input1c-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU2-LeftRL_EntryID#
Command1=[!SetVariable GPU2-LeftRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-LeftRL_EntryID [Input1c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input1d-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLLeft_MaxValue#
Command1=[!SetVariable GPU2_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLLeft_MaxValue [Input1d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]

[Input1e-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLLeft_MinValue#
Command1=[!SetVariable GPU2_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLLeft_MinValue [Input1e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: %1
Hidden=#GPU2HideHWiNFO#

[Input2a-BG]
Meter=Shape
Shape=Rectangle 260,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2a-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input2b-BG]
Meter=Shape
Shape=Rectangle 270,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2b-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input2c-BG]
Meter=Shape
Shape=Rectangle 270,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2c-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input2d-BG]
Meter=Shape
Shape=Rectangle 280,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2d-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input2e-BG]
Meter=Shape
Shape=Rectangle 280,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2e-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#
[Input2a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=281
Text=SensorID: #GPU2-RightRL_Id#
Hidden=#GPU2HideHWiNFO#
[Input2b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=301
Text=Instance: #GPU2-RightRL_Instance#
Hidden=#GPU2HideHWiNFO#
[Input2c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=321
Text=EntryID: #GPU2-RightRL_EntryID#
Hidden=#GPU2HideHWiNFO#
[Input2d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=341
Text=Max: #GPU2_RLRight_MaxValue#
Hidden=#GPU2HideHWiNFO#
[Input2e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=361
Text=Min: #GPU2_RLRight_MinValue#
Hidden=#GPU2HideHWiNFO#

[Input2a-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#GPU2-RightRL_Id#
Command1=[!SetVariable GPU2-RightRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-RightRL_Id [Input2a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input2b-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU2-RightRL_Instance#
Command1=[!SetVariable GPU2-RightRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-RightRL_Instance [Input2b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input2c-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU2-RightRL_EntryID#
Command1=[!SetVariable GPU2-RightRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-RightRL_EntryID [Input2c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input2d-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLRight_MaxValue#
Command1=[!SetVariable GPU2_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLRight_MaxValue [Input2d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]

[Input2e-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLRight_MinValue#
Command1=[!SetVariable GPU2_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLRight_MinValue [Input2e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=386
Text=GPU2 Name:
Hidden=#GPU2HideHWiNFO#

[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#GPU2HideHWiNFO#

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideHWiNFO#

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#GPU2Name#
Hidden=#GPU2HideHWiNFO#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU2Name#
Command1=[!SetVariable GPU2Name "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2Name [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


;---- HWiNFO Sensors

[HWiNFO-Divider2]
Meter=Shape
Shape=Rectangle 12,410,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#GPU2HideHWiNFO#

[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
Hidden=#GPU2HideHWiNFO#
StringAlign=Right
X=360
Y=420
Text="Sensor ID        Instance         Entry ID"

;-- Configuration Input -------------------------------------------------------------------------------- 

[Input4-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=441
Text="GPU2 Core Load"
Hidden=#GPU2HideHWiNFO#

[Input4a-BG]
Meter=Shape
Shape=Rectangle 160,440,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4a-Field "ExecuteBatch 1-2"]
[Input4b-BG]
Meter=Shape
Shape=Rectangle 250,440,40,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]
[Input4c-BG]
Meter=Shape
Shape=Rectangle 300,440,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4c-Field "ExecuteBatch 1-2"]

[Input4a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=441
Text=#GPU2-CoreLoad_ID#
Hidden=#GPU2HideHWiNFO#
[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU2-CoreLoad_Instance#
Hidden=#GPU2HideHWiNFO#
[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU2-CoreLoad_EntryID#
Hidden=#GPU2HideHWiNFO#

[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-CoreLoad_ID#
Command1=[!SetVariable GPU2-CoreLoad_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-CoreLoad_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=441
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU2-CoreLoad_Instance#
Command1=[!SetVariable GPU2-CoreLoad_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-CoreLoad_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-CoreLoad_EntryID#
Command1=[!SetVariable GPU2-CoreLoad_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-CoreLoad_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=461
Text="GPU2 Temperature"
Hidden=#GPU2HideHWiNFO#

[Input5a-BG]
Meter=Shape
Shape=Rectangle 160,460,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5a-Field "ExecuteBatch 1-2"]
[Input5b-BG]
Meter=Shape
Shape=Rectangle 250,460,40,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5b-Field "ExecuteBatch 1-2"]
[Input5c-BG]
Meter=Shape
Shape=Rectangle 300,460,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5c-Field "ExecuteBatch 1-2"]

[Input5a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=461
Text=#GPU2-Temp_ID#
Hidden=#GPU2HideHWiNFO#
[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU2-Temp_Instance#
Hidden=#GPU2HideHWiNFO#
[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU2-Temp_EntryID#
Hidden=#GPU2HideHWiNFO#

[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-Temp_ID#
Command1=[!SetVariable GPU2-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Temp_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=461
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU2-Temp_Instance#
Command1=[!SetVariable GPU2-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Temp_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-Temp_EntryID#
Command1=[!SetVariable GPU2-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Temp_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=481
Text="GPU2 FAN1"
Hidden=#GPU2HideHWiNFO#

[Input6a-BG]
Meter=Shape
Shape=Rectangle 160,480,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6a-Field "ExecuteBatch 1-2"]
[Input6b-BG]
Meter=Shape
Shape=Rectangle 250,480,40,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6b-Field "ExecuteBatch 1-2"]
[Input6c-BG]
Meter=Shape
Shape=Rectangle 300,480,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6c-Field "ExecuteBatch 1-2"]

[Input6a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=481
Text=#GPU2-FAN1_ID#
Hidden=#GPU2HideHWiNFO#
[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU2-FAN1_Instance#
Hidden=#GPU2HideHWiNFO#
[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU2-FAN1_EntryID#
Hidden=#GPU2HideHWiNFO#

[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-FAN1_ID#
Command1=[!SetVariable GPU2-FAN1_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-FAN1_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=481
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU2-FAN1_Instance#
Command1=[!SetVariable GPU2-FAN1_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-FAN1_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-FAN1_EntryID#
Command1=[!SetVariable GPU2-FAN1_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-FAN1_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=501
Text="GPU2 FAN2"
Hidden=#GPU2HideHWiNFO#

[Input7a-BG]
Meter=Shape
Shape=Rectangle 160,500,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7a-Field "ExecuteBatch 1-2"]
[Input7b-BG]
Meter=Shape
Shape=Rectangle 250,500,40,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7b-Field "ExecuteBatch 1-2"]
[Input7c-BG]
Meter=Shape
Shape=Rectangle 300,500,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7c-Field "ExecuteBatch 1-2"]

[Input7a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=501
Text=#GPU2-FAN2_ID#
Hidden=#GPU2HideHWiNFO#
[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU2-FAN2_Instance#
Hidden=#GPU2HideHWiNFO#
[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU2-FAN2_EntryID#
Hidden=#GPU2HideHWiNFO#

[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-FAN2_ID#
Command1=[!SetVariable GPU2-FAN2_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-FAN2_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=501
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU2-FAN2_Instance#
Command1=[!SetVariable GPU2-FAN2_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-FAN2_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-FAN2_EntryID#
Command1=[!SetVariable GPU2-FAN2_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-FAN2_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


[Input8-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=521
Text="GPU2 Dedicated Memory"
Hidden=#GPU2HideHWiNFO#

[Input8a-BG]
Meter=Shape
Shape=Rectangle 160,520,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8a-Field "ExecuteBatch 1-2"]
[Input8b-BG]
Meter=Shape
Shape=Rectangle 250,520,40,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8b-Field "ExecuteBatch 1-2"]
[Input8c-BG]
Meter=Shape
Shape=Rectangle 300,520,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8c-Field "ExecuteBatch 1-2"]

[Input8a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=521
Text=#GPU2-VRAM_ID#
Hidden=#GPU2HideHWiNFO#
[Input8b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU2-VRAM_Instance#
Hidden=#GPU2HideHWiNFO#
[Input8c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU2-VRAM_EntryID#
Hidden=#GPU2HideHWiNFO#

[Input8a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-VRAM_ID#
Command1=[!SetVariable GPU2-VRAM_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-VRAM_ID [Input8a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input8b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=521
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU2-VRAM_Instance#
Command1=[!SetVariable GPU2-VRAM_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-VRAM_Instance [Input8b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input8c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-VRAM_EntryID#
Command1=[!SetVariable GPU2-VRAM_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-VRAM_EntryID [Input8c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]

[Input9-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=541
Text="GPU2 Power"
Hidden=#GPU2HideHWiNFO#

[Input9a-BG]
Meter=Shape
Shape=Rectangle 160,540,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9a-Field "ExecuteBatch 1-2"]
[Input9b-BG]
Meter=Shape
Shape=Rectangle 250,540,40,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9b-Field "ExecuteBatch 1-2"]
[Input9c-BG]
Meter=Shape
Shape=Rectangle 300,540,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9c-Field "ExecuteBatch 1-2"]

[Input9a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=541
Text=#GPU2-Power_ID#
Hidden=#GPU2HideHWiNFO#
[Input9b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU2-Power_Instance#
Hidden=#GPU2HideHWiNFO#
[Input9c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU2-Power_EntryID#
Hidden=#GPU2HideHWiNFO#

[Input9a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-Power_ID#
Command1=[!SetVariable GPU2-Power_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Power_ID [Input9a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input9b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=541
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU2-Power_Instance#
Command1=[!SetVariable GPU2-Power_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Power_Instance [Input9b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input9c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-Power_EntryID#
Command1=[!SetVariable GPU2-Power_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Power_EntryID [Input9c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


[Input10-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=561
Text="GPU2 Clock"
Hidden=#GPU2HideHWiNFO#

[Input10a-BG]
Meter=Shape
Shape=Rectangle 160,560,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10a-Field "ExecuteBatch 1-2"]
[Input10b-BG]
Meter=Shape
Shape=Rectangle 250,560,40,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10b-Field "ExecuteBatch 1-2"]
[Input10c-BG]
Meter=Shape
Shape=Rectangle 300,560,80,15,3 | Fill Color 0,0,0
Hidden=#GPU2HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10c-Field "ExecuteBatch 1-2"]

[Input10a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=561
Text=#GPU2-Clock_ID#
Hidden=#GPU2HideHWiNFO#
[Input10b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU2-Clock_Instance#
Hidden=#GPU2HideHWiNFO#
[Input10c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU2-Clock_EntryID#
Hidden=#GPU2HideHWiNFO#

[Input10a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-Clock_ID#
Command1=[!SetVariable GPU2-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Clock_ID [Input10a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input10b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=561
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU2-Clock_Instance#
Command1=[!SetVariable GPU2-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Clock_Instance [Input10b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
[Input10c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU2-Clock_EntryID#
Command1=[!SetVariable GPU2-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2-Clock_EntryID [Input10c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]


;-- HWiNFO SM Viewer ---------------------------------------------------------------------------------- 

[HWiNFOSMV]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=700
LeftMouseUpAction=["#@#Tools\HWiNFOSharedMemoryViewer.exe]
Hidden=#GPU2HideHWiNFO#
[HWiNFOSMVText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Open HWiNFO Shared Memory Viewer"
Hidden=#GPU2HideHWiNFO#


;-- MSI Afterburner -------------------------------------------------------------------------------- 

[MSIAB-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Hidden=#GPU2HideMSIAB#

[MSIAB-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=MSI Afterburner
Hidden=#GPU2HideMSIAB#

[MSIAB_Status]
Measure=Plugin
Plugin=Process
ProcessName=MSIAfterburner.exe
RegExpSubstitute=1
Substitute="-1":"not running","1":"running"
IfCondition=(MSIAB_Status = 1)
IfTrueAction=[!SetOption MSIAB_StatusText FontColor "0,255,0"]
IfFalseAction=[!SetOption MSIAB_StatusText FontColor "255,0,0"]

[MSIAB_StatusText]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=MSIAB_Status
StringAlign=Right
Y=220
X=380
Text=%1
Hidden=#GPU2HideMSIAB#

[MSIAB-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Hidden=#GPU2HideMSIAB#

[MSIAB-LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------
Hidden=#GPU2HideMSIAB#

[MSIAB-RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------
Hidden=#GPU2HideMSIAB#

[MSIAB_Image]
Meter=Image
ImageName=#@#Images\General\MSIAB-GPU.png
X=137
Y=275
W=125
Hidden=#GPU2HideMSIAB#


;---- Title ----

[MSIAB-Input1-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=566
Text=GPU2 Name:
Hidden=#GPU2HideMSIAB#

[MSIAB-Input1-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=566
Text=(%1 = AutoDetect)
Hidden=#GPU2HideMSIAB#

[MSIAB-Input1-BG]
Meter=Shape
Shape=Rectangle 150,565,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-Input1-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideMSIAB#

[MSIAB-Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=566
Text=#GPU2NameMSIAB#
Hidden=#GPU2HideMSIAB#

[MSIAB-Input1-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=566
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU2NameMSIAB#
Command1=[!SetVariable GPU2NameMSIAB "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2NameMSIAB [MSIAB-Input1-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
Hidden=#GPU2HideMSIAB#


;---- MSIAB Left Roundline Min/Max ---- 

[MSIAB-InputLR-Max-BG]
Meter=Shape
Shape=Rectangle 15,260,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputLR-Max-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputLR-Max-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=261
Text=Max: #GPU2_RLLeft_MaxValue# [#SensorUnit[#GPU2_RLLeft_ID]]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputLR-Max-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=261
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLLeft_MaxValue#
Command1=[!SetVariable GPU2_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLLeft_MaxValue [MSIAB-InputLR-Max-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputLR-Min-BG]
Meter=Shape
Shape=Rectangle 15,535,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputLR-Min-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputLR-Min-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=536
Text=Min: #GPU2_RLLeft_MinValue# [#SensorUnit[#GPU2_RLLeft_ID]]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputLR-Min-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=536
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLLeft_MinValue#
Command1=[!SetVariable GPU2_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLLeft_MinValue [MSIAB-InputLR-Min-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
Hidden=#GPU2HideMSIAB#


;---- MSIAB Left Roundline Selection ---- 

[MSIAB_Active_LeftRL]
Measure=Calc
Formula=#GPU2_RLLeft_ID#
IfCondition=(MSIAB_Active_LeftRL = 0)
IfTrueAction=[!SetOption MSIAB-Select1 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition2=(MSIAB_Active_LeftRL = 16)
IfTrueAction2=[!SetOption MSIAB-Select2 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition3=(MSIAB_Active_LeftRL = 18)
IfTrueAction3=[!SetOption MSIAB-Select3 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition4=(MSIAB_Active_LeftRL = 20)
IfTrueAction4=[!SetOption MSIAB-Select4 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition5=(MSIAB_Active_LeftRL = 32)
IfTrueAction5=[!SetOption MSIAB-Select5 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition6=(MSIAB_Active_LeftRL = 34)
IfTrueAction6=[!SetOption MSIAB-Select6 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition7=(MSIAB_Active_LeftRL = 48)
IfTrueAction7=[!SetOption MSIAB-Select7 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition8=(MSIAB_Active_LeftRL = 49)
IfTrueAction8=[!SetOption MSIAB-Select8 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition9=(MSIAB_Active_LeftRL = 64)
IfTrueAction9=[!SetOption MSIAB-Select9 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition10=(MSIAB_Active_LeftRL = 96)
IfTrueAction10=[!SetOption MSIAB-Select10 ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[MSIAB-Select1]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=115	
Y=285
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 0 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#

[MSIAB-TextSelect1]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName0#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select2]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 16 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect2]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName16#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select3]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 18 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect3]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName18#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select4]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 20 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect4]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName20#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select5]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 32 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect5]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName32#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select6]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 34 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect6]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName34#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select7]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 48 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect7]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName48#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select8]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 49 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect8]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName49#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select9]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 64 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect9]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName64#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select10]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLLeft_ID 96 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect10]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName96#
Hidden=#GPU2HideMSIAB#


;---- MSIAB Right Roundline Min/Max ---- 

[MSIAB-InputRR-Max-BG]
Meter=Shape
Shape=Rectangle 270,260,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputRR-Max-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputRR-Max-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=271
Y=261
Text=Max: #GPU2_RLRight_MaxValue# [#SensorUnit[#GPU2_RLRight_ID]]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputRR-Max-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=261
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLRight_MaxValue#
Command1=[!SetVariable GPU2_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLRight_MaxValue [MSIAB-InputRR-Max-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputRR-Min-BG]
Meter=Shape
Shape=Rectangle 270,535,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputRR-Min-Field "ExecuteBatch 1-2"]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputRR-Min-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=271
Y=536
Text=Min: #GPU2_RLRight_MinValue# [#SensorUnit[#GPU2_RLRight_ID]]
Hidden=#GPU2HideMSIAB#

[MSIAB-InputRR-Min-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=536
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU2_RLRight_MinValue#
Command1=[!SetVariable GPU2_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU2_RLRight_MinValue [MSIAB-InputRR-Min-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Update]
Hidden=#GPU2HideMSIAB#

;---- MSIAB Left Roundline Selection ---- 

[MSIAB_Active_RightRL]
Measure=Calc
Formula=#GPU2_RLRight_ID#
IfCondition=(MSIAB_Active_RightRL = 0)
IfTrueAction=[!SetOption MSIAB-Select1b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition2=(MSIAB_Active_RightRL = 16)
IfTrueAction2=[!SetOption MSIAB-Select2b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition3=(MSIAB_Active_RightRL = 18)
IfTrueAction3=[!SetOption MSIAB-Select3b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition4=(MSIAB_Active_RightRL = 20)
IfTrueAction4=[!SetOption MSIAB-Select4b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition5=(MSIAB_Active_RightRL = 32)
IfTrueAction5=[!SetOption MSIAB-Select5b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition6=(MSIAB_Active_RightRL = 34)
IfTrueAction6=[!SetOption MSIAB-Select6b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition7=(MSIAB_Active_RightRL = 48)
IfTrueAction7=[!SetOption MSIAB-Select7b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition8=(MSIAB_Active_RightRL = 49)
IfTrueAction8=[!SetOption MSIAB-Select8b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition9=(MSIAB_Active_RightRL = 64)
IfTrueAction9=[!SetOption MSIAB-Select9b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition10=(MSIAB_Active_RightRL = 96)
IfTrueAction10=[!SetOption MSIAB-Select10b ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[MSIAB-Select1b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=270	
Y=285
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 0 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#

[MSIAB-TextSelect1b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName0#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 16 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect2b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName16#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select3b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 18 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect3b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName18#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select4b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 20 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect4b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName20#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select5b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 32 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect5b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName32#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select6b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 34 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect6b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName34#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select7b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 48 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect7b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName48#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select8b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 49 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect8b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName49#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select9b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 64 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect9b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName64#
Hidden=#GPU2HideMSIAB#

[MSIAB-Select10b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU2_RLRight_ID 96 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU2"][!Refresh "#ROOTCONFIG#\Panels\GPU2"][!Refresh]
Hidden=#GPU2HideMSIAB#
[MSIAB-TextSelect10b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName96#
Hidden=#GPU2HideMSIAB#