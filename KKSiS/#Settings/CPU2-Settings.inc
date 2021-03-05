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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\CPU2" "CPU2.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\CPU2" "CPU2.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-CPU2Size" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-CPU2Size" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-CPU2Size" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"]
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
ButtonImage=#@#Images\Buttons\Hide#CPU2HideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPU2HideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#CPUHideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPU2HideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#CPU2HideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPU2HideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#CPU2HideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPU2HideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#CPU2ColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPU2ColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#CPU2ColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPU2ColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]


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
X=75
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "CPUFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "CPUFormat2" "" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]

[Technology1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=6r
Text=HWiNFO 1

[Technology2Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=100r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "CPUFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "CPUFormat2" "2" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh]

[Technology2Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=6r
Text=HWiNFO 2



;-- HWiNFO -------------------------------------------------------------------------------- 

[HWiNFO-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50

[HWiNFO-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=HWiNFO


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


[HWiNFO-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160



[HWiNFO_Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-LeftRL_Id#
HWiNFOSensorInstance=#CPU2-LeftRL_Instance#
HWiNFOEntryId		=#CPU2-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1



[HWiNFO_Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU2-RightRL_Id#
HWiNFOSensorInstance=#CPU2-RightRL_Instance#
HWiNFOEntryId		=#CPU2-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1


[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-CPU.png
X=135
Y=265
W=125



;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Measure_LeftRL_Name
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: %1


[Input1a-BG]
Meter=Shape
Shape=Rectangle 15,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1a-Field "ExecuteBatch 1-2"]

[Input1b-BG]
Meter=Shape
Shape=Rectangle 15,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1b-Field "ExecuteBatch 1-2"]

[Input1c-BG]
Meter=Shape
Shape=Rectangle 15,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1c-Field "ExecuteBatch 1-2"]

[Input1d-BG]
Meter=Shape
Shape=Rectangle 15,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1d-Field "ExecuteBatch 1-2"]

[Input1e-BG]
Meter=Shape
Shape=Rectangle 15,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1e-Field "ExecuteBatch 1-2"]

[Input1a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=281
Text=SensorID: #CPU2-LeftRL_Id#

[Input1b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=301
Text=Instance: #CPU2-LeftRL_Instance#

[Input1c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=321
Text=EntryID: #CPU2-LeftRL_EntryID#

[Input1d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=341
Text=Max: #CPU2_RLLeft_MaxValue#

[Input1e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=361
Text=Min: #CPU2_RLLeft_MinValue#


[Input1a-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#CPU2-LeftRL_Id#
Command1=[!SetVariable CPU2-LeftRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-LeftRL_Id [Input1a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input1b-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU2-LeftRL_Instance#
Command1=[!SetVariable CPU2-LeftRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-LeftRL_Instance [Input1b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input1c-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU2-LeftRL_EntryID#
Command1=[!SetVariable CPU2-LeftRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-LeftRL_EntryID [Input1c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input1d-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU2_RLLeft_MaxValue#
Command1=[!SetVariable CPU2_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2_RLLeft_MaxValue [Input1d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]

[Input1e-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU2_RLLeft_MinValue#
Command1=[!SetVariable CPU2_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2_RLLeft_MinValue [Input1e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: %1


[Input2a-BG]
Meter=Shape
Shape=Rectangle 260,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2a-Field "ExecuteBatch 1-2"]

[Input2b-BG]
Meter=Shape
Shape=Rectangle 270,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2b-Field "ExecuteBatch 1-2"]

[Input2c-BG]
Meter=Shape
Shape=Rectangle 270,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2c-Field "ExecuteBatch 1-2"]

[Input2d-BG]
Meter=Shape
Shape=Rectangle 280,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2d-Field "ExecuteBatch 1-2"]

[Input2e-BG]
Meter=Shape
Shape=Rectangle 280,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2e-Field "ExecuteBatch 1-2"]

[Input2a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=281
Text=SensorID: #CPU2-RightRL_Id#

[Input2b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=301
Text=Instance: #CPU2-RightRL_Instance#

[Input2c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=321
Text=EntryID: #CPU2-RightRL_EntryID#

[Input2d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=341
Text=Max: #CPU2_RLRight_MaxValue#

[Input2e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=361
Text=Min: #CPU2_RLRight_MinValue#


[Input2a-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#CPU2-RightRL_Id#
Command1=[!SetVariable CPU2-RightRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-RightRL_Id [Input2a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input2b-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU2-RightRL_Instance#
Command1=[!SetVariable CPU2-RightRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-RightRL_Instance [Input2b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input2c-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU2-RightRL_EntryID#
Command1=[!SetVariable CPU2-RightRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-RightRL_EntryID [Input2c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input2d-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU2_RLRight_MaxValue#
Command1=[!SetVariable CPU2_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2_RLRight_MaxValue [Input2d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]

[Input2e-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU2_RLRight_MinValue#
Command1=[!SetVariable CPU2_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2_RLRight_MinValue [Input2e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=386
Text=CPU2 Name:


[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)


[Input3-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]


[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#CPU2Name#


[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU2Name#
Command1=[!SetVariable CPU2Name "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2Name [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


;---- HWiNFO Sensors

[HWiNFO-Divider2]
Meter=Shape
Shape=Rectangle 12,410,375,2,0 | Fill Color 160,160,160



[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text

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
Text="Total CPU Usage"


[Input4a-BG]
Meter=Shape
Shape=Rectangle 160,440,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input4a-Field "ExecuteBatch 1-2"]
[Input4b-BG]
Meter=Shape
Shape=Rectangle 250,440,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]
[Input4c-BG]
Meter=Shape
Shape=Rectangle 300,440,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input4c-Field "ExecuteBatch 1-2"]

[Input4a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=441
Text=#CPU2-Usage-Total_ID#

[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2-Usage-Total_Instance#

[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2-Usage-Total_EntryID#


[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-Usage-Total_ID#
Command1=[!SetVariable CPU2-Usage-Total_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-Usage-Total_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=441
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2-Usage-Total_Instance#
Command1=[!SetVariable CPU2-Usage-Total_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-Usage-Total_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-Usage-Total_EntryID#
Command1=[!SetVariable CPU2-Usage-Total_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-Usage-Total_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=461
Text="CPU Temperature"


[Input5a-BG]
Meter=Shape
Shape=Rectangle 160,460,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input5a-Field "ExecuteBatch 1-2"]
[Input5b-BG]
Meter=Shape
Shape=Rectangle 250,460,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input5b-Field "ExecuteBatch 1-2"]
[Input5c-BG]
Meter=Shape
Shape=Rectangle 300,460,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input5c-Field "ExecuteBatch 1-2"]

[Input5a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=461
Text=#CPU2-Temp_ID#

[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2-Temp_Instance#

[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2-Temp_EntryID#


[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-Temp_ID#
Command1=[!SetVariable CPU2-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-Temp_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=461
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2-Temp_Instance#
Command1=[!SetVariable CPU2-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-Temp_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-Temp_EntryID#
Command1=[!SetVariable CPU2-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-Temp_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=481
Text="CPU FAN1"


[Input6a-BG]
Meter=Shape
Shape=Rectangle 160,480,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input6a-Field "ExecuteBatch 1-2"]
[Input6b-BG]
Meter=Shape
Shape=Rectangle 250,480,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input6b-Field "ExecuteBatch 1-2"]
[Input6c-BG]
Meter=Shape
Shape=Rectangle 300,480,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input6c-Field "ExecuteBatch 1-2"]

[Input6a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=481
Text=#CPU2-FAN1_ID#

[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2-FAN1_Instance#

[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2-FAN1_EntryID#


[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-FAN1_ID#
Command1=[!SetVariable CPU2-FAN1_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-FAN1_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=481
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2-FAN1_Instance#
Command1=[!SetVariable CPU2-FAN1_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-FAN1_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-FAN1_EntryID#
Command1=[!SetVariable CPU2-FAN1_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-FAN1_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=501
Text="CPU FAN2"


[Input7a-BG]
Meter=Shape
Shape=Rectangle 160,500,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input7a-Field "ExecuteBatch 1-2"]
[Input7b-BG]
Meter=Shape
Shape=Rectangle 250,500,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input7b-Field "ExecuteBatch 1-2"]
[Input7c-BG]
Meter=Shape
Shape=Rectangle 300,500,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input7c-Field "ExecuteBatch 1-2"]

[Input7a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=501
Text=#CPU2-FAN2_ID#

[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2-FAN2_Instance#

[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2-FAN2_EntryID#


[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-FAN2_ID#
Command1=[!SetVariable CPU2-FAN2_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-FAN2_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=501
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2-FAN2_Instance#
Command1=[!SetVariable CPU2-FAN2_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-FAN2_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-FAN2_EntryID#
Command1=[!SetVariable CPU2-FAN2_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-FAN2_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


[Input8-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=521
Text="CPU VCore/VID"


[Input8a-BG]
Meter=Shape
Shape=Rectangle 160,520,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input8a-Field "ExecuteBatch 1-2"]
[Input8b-BG]
Meter=Shape
Shape=Rectangle 250,520,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input8b-Field "ExecuteBatch 1-2"]
[Input8c-BG]
Meter=Shape
Shape=Rectangle 300,520,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input8c-Field "ExecuteBatch 1-2"]

[Input8a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=521
Text=#CPU2-VCore_ID#

[Input8b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2-VCore_Instance#

[Input8c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2-VCore_EntryID#


[Input8a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-VCore_ID#
Command1=[!SetVariable CPU2-VCore_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-VCore_ID [Input8a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input8b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=521
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2-VCore_Instance#
Command1=[!SetVariable CPU2-VCore_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-VCore_Instance [Input8b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input8c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-VCore_EntryID#
Command1=[!SetVariable CPU2-VCore_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-VCore_EntryID [Input8c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]

[Input9-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=541
Text="CPU Package Power"


[Input9a-BG]
Meter=Shape
Shape=Rectangle 160,540,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input9a-Field "ExecuteBatch 1-2"]
[Input9b-BG]
Meter=Shape
Shape=Rectangle 250,540,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input9b-Field "ExecuteBatch 1-2"]
[Input9c-BG]
Meter=Shape
Shape=Rectangle 300,540,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input9c-Field "ExecuteBatch 1-2"]

[Input9a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=541
Text=#CPU2-PackagePwr_ID#

[Input9b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2-PackagePwr_Instance#

[Input9c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2-PackagePwr_EntryID#


[Input9a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-PackagePwr_ID#
Command1=[!SetVariable CPU2-PackagePwr_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-PackagePwr_ID [Input9a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input9b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=541
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2-PackagePwr_Instance#
Command1=[!SetVariable CPU2-PackagePwr_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-PackagePwr_Instance [Input9b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input9c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2-PackagePwr_EntryID#
Command1=[!SetVariable CPU2-PackagePwr_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2-PackagePwr_EntryID [Input9c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


[Input10-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=561
Text="CPU1x Frequency/Clock"


[Input10a-BG]
Meter=Shape
Shape=Rectangle 160,560,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input10a-Field "ExecuteBatch 1-2"]
[Input10b-BG]
Meter=Shape
Shape=Rectangle 250,560,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input10b-Field "ExecuteBatch 1-2"]
[Input10c-BG]
Meter=Shape
Shape=Rectangle 300,560,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input10c-Field "ExecuteBatch 1-2"]

[Input10a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=561
Text=#CPU2A-Clock_ID#

[Input10b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2A-Clock_Instance#

[Input10c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2A-Clock_EntryID#


[Input10a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2A-Clock_ID#
Command1=[!SetVariable CPU2A-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2A-Clock_ID [Input10a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input10b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=561
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2A-Clock_Instance#
Command1=[!SetVariable CPU2A-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2A-Clock_Instance [Input10b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input10c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2A-Clock_EntryID#
Command1=[!SetVariable CPU2A-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2A-Clock_EntryID [Input10c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


[Input11-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=581
Text="CPU2x Frequency/Clock"


[Input11a-BG]
Meter=Shape
Shape=Rectangle 160,580,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input11a-Field "ExecuteBatch 1-2"]
[Input11b-BG]
Meter=Shape
Shape=Rectangle 250,580,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input11b-Field "ExecuteBatch 1-2"]
[Input11c-BG]
Meter=Shape
Shape=Rectangle 300,580,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input11c-Field "ExecuteBatch 1-2"]

[Input11a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=581
Text=#CPU2B-Clock_ID#

[Input11b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2B-Clock_Instance#

[Input11c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2B-Clock_EntryID#


[Input11a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=581
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2B-Clock_ID#
Command1=[!SetVariable CPU2B-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2B-Clock_ID [Input11a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input11b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=581
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2B-Clock_Instance#
Command1=[!SetVariable CPU2B-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2B-Clock_Instance [Input11b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input11c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=581
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2B-Clock_EntryID#
Command1=[!SetVariable CPU2B-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2B-Clock_EntryID [Input11c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]


[Input12-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=601
Text="CPU3x Frequency/Clock"


[Input12a-BG]
Meter=Shape
Shape=Rectangle 160,600,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input12a-Field "ExecuteBatch 1-2"]
[Input12b-BG]
Meter=Shape
Shape=Rectangle 250,600,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input12b-Field "ExecuteBatch 1-2"]
[Input12c-BG]
Meter=Shape
Shape=Rectangle 300,600,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input12c-Field "ExecuteBatch 1-2"]

[Input12a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=601
Text=#CPU2C-Clock_ID#

[Input12b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2C-Clock_Instance#

[Input12c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2C-Clock_EntryID#


[Input12a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=601
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2C-Clock_ID#
Command1=[!SetVariable CPU2C-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2C-Clock_ID [Input12a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input12b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=601
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2C-Clock_Instance#
Command1=[!SetVariable CPU2C-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2C-Clock_Instance [Input12b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input12c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=601
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2C-Clock_EntryID#
Command1=[!SetVariable CPU2C-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2C-Clock_EntryID [Input12c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]

[Input13-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=621
Text="CPU4x Frequency/Clock"


[Input13a-BG]
Meter=Shape
Shape=Rectangle 160,620,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input13a-Field "ExecuteBatch 1-2"]
[Input13b-BG]
Meter=Shape
Shape=Rectangle 250,620,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input13b-Field "ExecuteBatch 1-2"]
[Input13c-BG]
Meter=Shape
Shape=Rectangle 300,620,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input13c-Field "ExecuteBatch 1-2"]

[Input13a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=621
Text=#CPU2D-Clock_ID#

[Input13b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU2D-Clock_Instance#

[Input13c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU2D-Clock_EntryID#


[Input13a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=621
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2D-Clock_ID#
Command1=[!SetVariable CPU2D-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2D-Clock_ID [Input13a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input13b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=621
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU2D-Clock_Instance#
Command1=[!SetVariable CPU2D-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2D-Clock_Instance [Input13b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]
[Input13c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=621
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU2D-Clock_EntryID#
Command1=[!SetVariable CPU2D-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU2D-Clock_EntryID [Input13c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU2"][!Refresh "#ROOTCONFIG#\Panels\CPU2"][!Update]

[Input14]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=670
LeftMouseUpAction=["#@#HWiNFO-Sensors.inc]

[Input14Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Manual Input Sensor Value"

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

