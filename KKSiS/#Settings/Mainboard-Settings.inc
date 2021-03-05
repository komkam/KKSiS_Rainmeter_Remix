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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Mainboard" "Mainboard.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Mainboard" "Mainboard.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-MainboardSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-MainboardSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-MainboardSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"]
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
ButtonImage=#@#Images\Buttons\Hide#MainboardHideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "MainboardHideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#MainboardHideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "MainboardHideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#MainboardHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "MainboardHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#MainboardHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "MainboardHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#MainboardColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "MainboardColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#MainboardColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "MainboardColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh]


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


[HWiNFO_Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Mainboard-LeftRL_Id#
HWiNFOSensorInstance=#Mainboard-LeftRL_Instance#
HWiNFOEntryId		=#Mainboard-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1

[HWiNFO_Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Mainboard-RightRL_Id0#
HWiNFOSensorInstance=#Mainboard-RightRL_Instance0#
HWiNFOEntryId		=#Mainboard-RightRL_EntryId0#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1

[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-Mainboard.png
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
Text=----- #VarLeftRL# ------#CRLF#Name: %1


[Input1a-BG]
Meter=Shape
Shape=Rectangle 15,205,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1a-Field "ExecuteBatch 1-2"]

[Input1b-BG]
Meter=Shape
Shape=Rectangle 15,225,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1b-Field "ExecuteBatch 1-2"]

[Input1c-BG]
Meter=Shape
Shape=Rectangle 15,245,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1c-Field "ExecuteBatch 1-2"]

[Input1d-BG]
Meter=Shape
Shape=Rectangle 15,265,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1d-Field "ExecuteBatch 1-2"]

[Input1e-BG]
Meter=Shape
Shape=Rectangle 15,285,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1e-Field "ExecuteBatch 1-2"]

[Input1a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=206
Text=SensorID: #Mainboard-LeftRL_Id#

[Input1b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=226
Text=Instance: #Mainboard-LeftRL_Instance#

[Input1c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=246
Text=EntryID: #Mainboard-LeftRL_EntryID#

[Input1d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=266
Text=Max: #Mainboard_RLLeft_MaxValue#

[Input1e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=286
Text=Min: #Mainboard_RLLeft_MinValue#


[Input1a-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=206
W=115
H=13
FocusDismiss=0
DefaultValue=#Mainboard-LeftRL_Id#
Command1=[!SetVariable Mainboard-LeftRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard-LeftRL_Id [Input1a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input1b-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=226
W=105
H=13
FocusDismiss=0
DefaultValue=#Mainboard-LeftRL_Instance#
Command1=[!SetVariable Mainboard-LeftRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard-LeftRL_Instance [Input1b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input1c-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=246
W=105
H=13
FocusDismiss=0
DefaultValue=#Mainboard-LeftRL_EntryID#
Command1=[!SetVariable Mainboard-LeftRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard-LeftRL_EntryID [Input1c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input1d-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=266
W=95
H=13
FocusDismiss=0
DefaultValue=#Mainboard_RLLeft_MaxValue#
Command1=[!SetVariable Mainboard_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard_RLLeft_MaxValue [Input1d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input1e-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=286
W=95
H=13
FocusDismiss=0
DefaultValue=#Mainboard_RLLeft_MinValue#
Command1=[!SetVariable Mainboard_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard_RLLeft_MinValue [Input1e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=165
Text=------ #VarRightRL# ------#CRLF#Name: %1


[Input2a-BG]
Meter=Shape
Shape=Rectangle 260,205,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2a-Field "ExecuteBatch 1-2"]

[Input2b-BG]
Meter=Shape
Shape=Rectangle 270,225,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2b-Field "ExecuteBatch 1-2"]

[Input2c-BG]
Meter=Shape
Shape=Rectangle 270,245,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2c-Field "ExecuteBatch 1-2"]

[Input2d-BG]
Meter=Shape
Shape=Rectangle 280,265,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2d-Field "ExecuteBatch 1-2"]

[Input2e-BG]
Meter=Shape
Shape=Rectangle 280,285,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2e-Field "ExecuteBatch 1-2"]

[Input2a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=206
Text=SensorID: [#Mainboard-RightRL_Id[#MainboardAllFansRL]]

[Input2b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=226
Text=Instance: [#Mainboard-RightRL_Instance[#MainboardAllFansRL]]

[Input2c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=246
Text=EntryID: [#Mainboard-RightRL_EntryID[#MainboardAllFansRL]]

[Input2d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=266
Text=Max: [#Mainboard_RLRight_MaxValue[#MainboardAllFansRL]]

[Input2e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=286
Text=Min: [#Mainboard_RLRight_MinValue[#MainboardAllFansRL]]


[Input2a-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=206
W=115
H=13
FocusDismiss=0
DefaultValue=[#Mainboard-RightRL_Id[#MainboardAllFansRL]]
Command1=[!SetVariable Mainboard-RightRL_Id0 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard-RightRL_Id0 [Input2a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input2b-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=226
W=105
H=13
FocusDismiss=0
DefaultValue=[#Mainboard-RightRL_Instance[#MainboardAllFansRL]]
Command1=[!SetVariable Mainboard-RightRL_Instance0 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard-RightRL_Instance0 [Input2b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input2c-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=246
W=105
H=13
FocusDismiss=0
DefaultValue=[#Mainboard-RightRL_EntryID[#MainboardAllFansRL]]
Command1=[!SetVariable Mainboard-RightRL_EntryID0 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard-RightRL_EntryID0 [Input2c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input2d-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=266
W=95
H=13
FocusDismiss=0
DefaultValue=[#Mainboard_RLRight_MaxValue[#MainboardAllFansRL]]
Command1=[!SetVariable Mainboard_RLRight_MaxValue#MainboardAllFansRL# "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard_RLRight_MaxValue#MainboardAllFansRL# [Input2d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]

[Input2e-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=286
W=95
H=13
FocusDismiss=0
DefaultValue=[#Mainboard_RLRight_MinValue[#MainboardAllFansRL]]
Command1=[!SetVariable Mainboard_RLRight_MinValue#MainboardAllFansRL# "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Mainboard_RLRight_MinValue#MainboardAllFansRL# [Input2e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=316
Text=Mainboard Name:


[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=316
Text=(%1 = AutoDetect)


[Input3-BG]
Meter=Shape
Shape=Rectangle 150,315,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]


[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=316
Text=#MainboardName#


[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=316
W=95
H=13
FocusDismiss=0
DefaultValue=#MainboardName#
Command1=[!SetVariable MainboardName "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MainboardName [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


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
Text="Chipset Temperature"

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
Text=#MB-PCH-Temp_ID#

[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#MB-PCH-Temp_Instance#

[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#MB-PCH-Temp_EntryID#


[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=366
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-PCH-Temp_ID#
Command1=[!SetVariable MB-PCH-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-PCH-Temp_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=366
W=35
H=13
FocusDismiss=0
DefaultValue=#MB-PCH-Temp_Instance#
Command1=[!SetVariable MB-PCH-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-PCH-Temp_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=366
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-PCH-Temp_EntryID#
Command1=[!SetVariable MB-PCH-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-PCH-Temp_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=386
Text="Sensor1 Temperature"

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
Text=#MB-Sensor-Temp_ID#

[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#MB-Sensor-Temp_Instance#

[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#MB-Sensor-Temp_EntryID#


[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=386
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-Sensor-Temp_ID#
Command1=[!SetVariable MB-Sensor-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-Sensor-Temp_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=386
W=35
H=13
FocusDismiss=0
DefaultValue=#MB-Sensor-Temp_Instance#
Command1=[!SetVariable MB-Sensor-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-Sensor-Temp_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=386
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-Sensor-Temp_EntryID#
Command1=[!SetVariable MB-Sensor-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-Sensor-Temp_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=406
Text="Mainboard Temperature"


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
Text=#MB-Temp_ID#

[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#MB-Temp_Instance#

[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#MB-Temp_EntryID#


[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=406
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-Temp_ID#
Command1=[!SetVariable MB-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-Temp_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=406
W=35
H=13
FocusDismiss=0
DefaultValue=#MB-Temp_Instance#
Command1=[!SetVariable MB-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-Temp_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=406
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-Temp_EntryID#
Command1=[!SetVariable MB-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-Temp_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=426
Text="System FAN1"

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
Text=#MB-FAN1_ID#

[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#MB-FAN1_Instance#

[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#MB-FAN1_EntryID#


[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=426
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN1_ID#
Command1=[!SetVariable MB-FAN1_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN1_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=426
W=35
H=13
FocusDismiss=0
DefaultValue=#MB-FAN1_Instance#
Command1=[!SetVariable MB-FAN1_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN1_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=426
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN1_EntryID#
Command1=[!SetVariable MB-FAN1_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN1_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


[Input8-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=446
Text="System FAN2"

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
Text=#MB-FAN2_ID#

[Input8b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#MB-FAN2_Instance#

[Input8c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#MB-FAN2_EntryID#


[Input8a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=446
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN2_ID#
Command1=[!SetVariable MB-FAN2_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN2_ID [Input8a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input8b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=446
W=35
H=13
FocusDismiss=0
DefaultValue=#MB-FAN2_Instance#
Command1=[!SetVariable MB-FAN2_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN2_Instance [Input8b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input8c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=446
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN2_EntryID#
Command1=[!SetVariable MB-FAN2_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN2_EntryID [Input8c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]

[Input9-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=466
Text="System FAN3"


[Input9a-BG]
Meter=Shape
Shape=Rectangle 160,465,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input9a-Field "ExecuteBatch 1-2"]
[Input9b-BG]
Meter=Shape
Shape=Rectangle 250,465,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input9b-Field "ExecuteBatch 1-2"]
[Input9c-BG]
Meter=Shape
Shape=Rectangle 300,465,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input9c-Field "ExecuteBatch 1-2"]

[Input9a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=466
Text=#MB-FAN3_ID#

[Input9b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#MB-FAN3_Instance#

[Input9c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#MB-FAN3_EntryID#


[Input9a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=466
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN3_ID#
Command1=[!SetVariable MB-FAN3_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN3_ID [Input9a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input9b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=466
W=35
H=13
FocusDismiss=0
DefaultValue=#MB-FAN3_Instance#
Command1=[!SetVariable MB-FAN3_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN3_Instance [Input9b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input9c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=466
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN3_EntryID#
Command1=[!SetVariable MB-FAN3_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN3_EntryID [Input9c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]


[Input10-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=486
Text="System FAN4"


[Input10a-BG]
Meter=Shape
Shape=Rectangle 160,485,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input10a-Field "ExecuteBatch 1-2"]
[Input10b-BG]
Meter=Shape
Shape=Rectangle 250,485,40,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input10b-Field "ExecuteBatch 1-2"]
[Input10c-BG]
Meter=Shape
Shape=Rectangle 300,485,80,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input10c-Field "ExecuteBatch 1-2"]

[Input10a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=486
Text=#MB-FAN4_ID#

[Input10b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#MB-FAN4_Instance#

[Input10c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#MB-FAN4_EntryID#


[Input10a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=486
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN4_ID#
Command1=[!SetVariable MB-FAN4_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN4_ID [Input10a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input10b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=486
W=35
H=13
FocusDismiss=0
DefaultValue=#MB-FAN4_Instance#
Command1=[!SetVariable MB-FAN4_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN4_Instance [Input10b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]
[Input10c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=486
W=75
H=13
FocusDismiss=0
DefaultValue=#MB-FAN4_EntryID#
Command1=[!SetVariable MB-FAN4_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables MB-FAN4_EntryID [Input10c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Update]

[InfoText1]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=510
Text=Info:

[InfoText2]
Meter=String
MeterStyle=SettingsStyle-Text
X=50
Y=510
Text=#VarMainboardInfo#


;---- Special Options ----

[HWiNFO-Divider3]
Meter=Shape
Shape=Rectangle 12,570,375,2,0 | Fill Color 160,160,160
Group=HWiNFO

[HWiNFO-SO-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=25
Y=575
Text="Special Options"


[MB-SOption1a]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=600
LeftMouseUpAction=[!WriteKeyValue Variables MainboardHideSensor 0 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh]

[MB-SOption1b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=600
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables MainboardHideSensor 1 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh]
Hidden=#MainboardHideSensor#

[MB-SOption1_Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=15r
Y=0r
Text=#VarHideSensor1#


[MB-SOption2a]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=620
LeftMouseUpAction=[!WriteKeyValue Variables MainboardHideBIOS 0 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh]

[MB-SOption2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=620
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables MainboardHideBIOS 1 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh]
Hidden=#MainboardHideBIOS#

[MB-SOption2_Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=15r
Y=0r
Text=#VarHideBIOS#


[MB-SOption3a]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=640
LeftMouseUpAction=[!WriteKeyValue Variables MainboardAllFansRL 0 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh]

[MB-SOption3b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=640
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables MainboardAllFansRL 1 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Mainboard"][!Refresh "#ROOTCONFIG#\Panels\Mainboard"][!Refresh]
Hidden=#MainboardAllFansRL#

[MB-SOption3_Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=15r
Y=0r
W=340
Text=#VarShowAllFans#
Clipstring=2

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

