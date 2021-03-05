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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Trash" "Trash.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Trash" "Trash.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-TRSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-TRSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-TRSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
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

[ButtonDescription3a]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarColored# (Panel)
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Panel-TRColored#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-TRColored" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Trash"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Panel-TRColored#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-TRColored" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Trash"][!Refresh]

[ButtonDescription3b]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarColored# (Circle)
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Circle-TRColored#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-TRColored" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Circle-TRColored#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Circle-TRColored" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh]

[Description3c]
Meter=String
MeterStyle=SettingsStyle-Text
Text=Max MByte
X=235
Y=110

[InputBG-1]
Meter=Shape
Shape=Rectangle 320,110,65,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-1 "ExecuteBatch 1-2"]

[InputText-1]
Meter=String
MeterStyle=SettingsStyle-Input
X=320
Y=111
Text=#TRMaxSize#
LeftMouseUpAction=[!CommandMeasure Input-1 "ExecuteBatch 1-2"]

[Input-1]
Measure=Plugin
Plugin=InputText
FontSize=8
W=62
X=321
Y=111
H=13
FocusDismiss=0
DefaultValue=#TRMaxSize#
Command1=[!SetVariable TRMaxSize "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables TRMaxSize [Input-1] "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh "#ROOTCONFIG#\Panels\Trash"][!Update]


;---- Bin Icon ----

[Background4]
Meter=Shape
Shape=Rectangle 10,140,380,105,3 | Fill Color 50,50,50

[Title4]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=145
Text=#VarTrash# #VarImage#

[Divider7]
Meter=Shape
Shape=Rectangle 12,160,376,2,0 | Fill Color 160,160,160

[BinIcon1]
Meter=Image
ImageName=#@#Images\General\Bin1a.png
X=20
Y=175
W=60
H=60
LeftMouseUpAction=[!WriteKeyValue Variables "TRBinType" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
MouseOverAction=[!SetOption BinIcon1 ImageName "#@#Images\General\Bin1b.png"][!Update]
MouseLeaveAction=[!SetOption BinIcon1 ImageName "#@#Images\General\Bin1a.png"][!Update]

[BinIcon2]
Meter=Image
ImageName=#@#Images\General\Bin2a.png
X=74r
Y=0r
W=60
H=60
LeftMouseUpAction=[!WriteKeyValue Variables "TRBinType" "2" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
MouseOverAction=[!SetOption BinIcon2 ImageName "#@#Images\General\Bin2b.png"][!Update]
MouseLeaveAction=[!SetOption BinIcon2 ImageName "#@#Images\General\Bin2a.png"][!Update]

[BinIcon3]
Meter=Image
ImageName=#@#Images\General\Bin3a.png
X=74r
Y=0r
W=60
H=60
LeftMouseUpAction=[!WriteKeyValue Variables "TRBinType" "3" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
MouseOverAction=[!SetOption BinIcon3 ImageName "#@#Images\General\Bin3b.png"][!Update]
MouseLeaveAction=[!SetOption BinIcon3 ImageName "#@#Images\General\Bin3a.png"][!Update]

[BinIcon4]
Meter=Image
ImageName=#@#Images\General\Bin4a.png
X=74r
Y=0r
W=60
H=60
LeftMouseUpAction=[!WriteKeyValue Variables "TRBinType" "4" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
MouseOverAction=[!SetOption BinIcon4 ImageName "#@#Images\General\Bin4b.png"][!Update]
MouseLeaveAction=[!SetOption BinIcon4 ImageName "#@#Images\General\Bin4a.png"][!Update]

[BinIcon5]
Meter=Image
ImageName=#@#Images\General\Bin5a.png
X=74r
Y=0r
W=60
H=60
LeftMouseUpAction=[!WriteKeyValue Variables "TRBinType" "5" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Trash"][!Refresh "#ROOTCONFIG#\Panels\Trash"]
MouseOverAction=[!SetOption BinIcon5 ImageName "#@#Images\General\Bin5b.png"][!Update]
MouseLeaveAction=[!SetOption BinIcon5 ImageName "#@#Images\General\Bin5a.png"][!Update]
