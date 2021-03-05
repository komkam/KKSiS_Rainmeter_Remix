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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\FritzBox" "FritzBox.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\FritzBox" "FritzBox.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-FritzBoxSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-FritzBoxSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-FritzBoxSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"]
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
Text=FB original AVM
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#FritzBoxColor#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FritzBoxColor" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#FritzBoxColor#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FritzBoxColor" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FritzBoxHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FritzBoxHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FritzBoxHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FritzBoxHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#FritzBoxColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FritzBoxColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#FritzBoxColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FritzBoxColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh]


;-- Skin Info -------------------------------------------------------------------------------- 

[Info-BG1]
Meter=Shape
Shape=Rectangle 10,140,380,265,3 | Fill Color 50,50,50
Group=Info

[Info-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=145
Text=Info
Group=Info

[Info-Divider1]
Meter=Shape
Shape=Rectangle 12,160,375,2,0 | Fill Color 160,160,160
Group=Info

[Info_Image]
Meter=Image
ImageName=#@#Images\General\Windows-FritzBox.png
X=135
Y=190
W=125

[Info-Arrows]
Meter=Shape
Shape=Line 120,175,180,200 | StrokeWidth 2 | Stroke Color 210,210,210
Shape2=Line 260,175,215,200 | StrokeWidth 2 | Stroke Color 210,210,210
Shape3=Line 115,215,180,220 | StrokeWidth 2 | Stroke Color 210,210,210
Shape4=Line 220,275,270,275 | StrokeWidth 2 | Stroke Color 210,210,210

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=Info_Measure_LeftRL_Name
X=15
Y=165
Text=DSL Uplink in bits/s#CRLF##CRLF#Current DL in Bytes/s#CRLF#Max DL in Bytes/s


[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=Info_Measure_RightRL_Name
X=380
Y=165
Text=DSL Downlink in bits/s#CRLF##CRLF##CRLF##CRLF##CRLF##CRLF#Current UL in Bytes/s#CRLF#Max UL in Bytes/s


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=Info_Measure_RightRL_Name
X=145
Y=316
Text=FritzBox Name:

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,315,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=316
Text=#FritzBoxName#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=316
W=95
H=13
FocusDismiss=0
DefaultValue=#FritzBoxName#
Command1=[!SetVariable FritzBoxName "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables FritzBoxName [Input3-Field] "#@#Info-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Update]

[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=316
Text=(%1 = AutoDetect)


[Input4-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=336
Text=IP Address:

[Input4-BG]
Meter=Shape
Shape=Rectangle 150,335,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input4-Field "ExecuteBatch 1-2"]

[Input4-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=336
Text=#FBIP#

[Input4-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=336
W=95
H=13
FocusDismiss=0
DefaultValue=#FBIP#
Command1=[!SetVariable FBIP "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables FBIP [Input4-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Update]


[Input5-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=356
Text=Username:

[Input5-BG]
Meter=Shape
Shape=Rectangle 150,355,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input5-Field "ExecuteBatch 1-2"]

[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=356
Text=#USER#

[Input5-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=356
W=95
H=13
FocusDismiss=0
DefaultValue=#USER#
Command1=[!SetVariable USER "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables USER [Input5-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Update]

[Input6-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=376
Text=Password:

[Input6-BG]
Meter=Shape
Shape=Rectangle 150,375,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input6-Field "ExecuteBatch 1-2"]

[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=376
Text="*******"

[Input6-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=376
W=95
H=13
FocusDismiss=0
DefaultValue="*******"
Command1=[!SetVariable PASS "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables PASS [Input6-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Update]


;-- FB Configuration -------------------------------------------------------------------------------- 

[Config-BG]
Meter=Shape
Shape=Rectangle 10,415,380,320,3 | Fill Color 50,50,50
Group=Info

[Config-Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=420
Text=Operating Mode

[Config-Divider]
Meter=Shape
Shape=Rectangle 12,435,375,2,0 | Fill Color 160,160,160

[Config_Image1]
Meter=Image
ImageName=#@#Images\General\FB_DSL.png
X=160
Y=460
W=200

[Config-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=460
X=20
Text=DSL: Internal Modem

[Config_Image2]
Meter=Image
ImageName=#@#Images\General\FB_WAN.png
X=160
Y=600
W=200

[Config-Text2]
Meter=String
MeterStyle=SettingsStyle-Text
Y=600
X=20
Text=WAN: External Modem

[FBMode_Selection]
Measure=String
String=#FritzBoxFormat3#
IfMatch=DSL
IfMatchAction=[!SetOption FBMode_SelectDSL ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch2=WAN
IfMatchAction2=[!SetOption FBMode_SelectWAN ButtonImage "#@#Images\Buttons\Checkbox1.png"]


[FBMode_SelectDSL]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=480
LeftMouseUpAction=[!WriteKeyValue Variables FritzBoxFormat3 "DSL" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh]
DynamicVariables=1

[FBMode_SelectWAN]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=620
LeftMouseUpAction=[!WriteKeyValue Variables FritzBoxFormat3 "WAN" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\FritzBox"][!Refresh "#ROOTCONFIG#\Panels\FritzBox"][!Refresh]
DynamicVariables=1

