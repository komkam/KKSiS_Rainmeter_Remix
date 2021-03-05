;---- Background ----

[Background1]
Meter=Shape
Shape=Rectangle 10,35,380,80,3 | Fill Color 50,50,50

[Title1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=40
Text=#VarBackgroundSetting#

[Divider1]
Meter=Shape
Shape=Rectangle 12,55,375,2,0 | Fill Color 180,180,180


[ButtonDescription11]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarPanelFrameShadow#
X=20
Y=70
[Button11a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Panel-HideBGShadow#a.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-HideBGShadow" "0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button11b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Panel-HideBGShadow#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-HideBGShadow" "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]


[ButtonDescription12]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBackgroundShadow#
X=40r
Y=0r
[Button12a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Panel-HideShadow#a.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-HideShadow" "0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button12b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Panel-HideShadow#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-HideShadow" "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]


[ButtonDescription13]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShadowColor#
X=20
Y=20r
[Button13a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnWhite.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-BGShadowColor" "255,255,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button13b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnBlack.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-BGShadowColor" "0,0,0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[ButtonMarker13]
Meter=Image
ImageName=#@#Images\Buttons\ColorCheckbox.png
X=-14r
Y=0r
DynamicVariables=1
[ButtonMeasure13]
Measure=String
String=#Panel-BGShadowColor#
IfMatch="0,0,0"
IfMatchAction=[!SetOption "ButtonMarker13" "X" "0r"][!UpdateMeter ButtonMarker13]


[ButtonDescription14]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarFrame#
X=212
Y=0r
[Button14a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Panel-Frame#a.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-Frame" "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button14b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Panel-Frame#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-Frame" "0" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]


;---- Font and Button Style ----

[Background2]
Meter=Shape
Shape=Rectangle 10,125,380,60,3 | Fill Color 50,50,50

[Title2]
Meter=String
MeterStyle=SettingsStyle-Text
Y=130
Text=#VarFontColor# & #VarButtonColor#

[Divider2]
Meter=Shape
Shape=Rectangle 12,145,375,2,0 | Fill Color 180,180,180


[ButtonDescription21]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarFontColor#
X=20
Y=160
[Button21a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnWhite.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-FontColor" "210,210,210,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button21b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnBlack.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-FontColor" "30,30,30,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[ButtonMarker21]
Meter=Image
ImageName=#@#Images\Buttons\ColorCheckbox.png
X=-14r
Y=0r
DynamicVariables=1
[ButtonMeasure21]
Measure=String
String=#Panel-FontColor#
IfMatch="30,30,30,255"
IfMatchAction=[!SetOption "ButtonMarker21" "X" "0r"][!UpdateMeter ButtonMarker21]


[ButtonDescription22]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarButtonColor#
X=212
Y=0r
[Button22a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnWhite.png
X=138r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-ButtonColor" "210,210,210,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button22b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnBlack.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Panel-ButtonColor" "30,30,30,255" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[ButtonMarker22]
Meter=Image
ImageName=#@#Images\Buttons\ColorCheckbox.png
X=-14r
Y=0r
DynamicVariables=1
[ButtonMeasure22]
Measure=String
String=#Panel-ButtonColor#
IfMatch="30,30,30,255"
IfMatchAction=[!SetOption "ButtonMarker22" "X" "0r"][!UpdateMeter ButtonMarker22]


;---- Background Color ----

[Background3]
Meter=Shape
Shape=Rectangle 10,195,380,65,3 | Fill Color 50,50,50

[Title3]
Meter=String
MeterStyle=SettingsStyle-Text
Y=200
Text=#VarBackgroundcolor#

[Divider3]
Meter=Shape
Shape=Rectangle 12,215,375,2,0 | Fill Color 180,180,180

[Description3a]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBackgroundColor# R,G,B,a
X=20
Y=230

[InputBG-1]
Meter=Shape
Shape=Rectangle 159,230,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-1 "ExecuteBatch 1-2"]

[InputText-1]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=231
Text=#Panel-BGColor#
LeftMouseUpAction=[!CommandMeasure Input-1 "ExecuteBatch 1-2"]

[Input-1]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=231
H=13
FocusDismiss=0
DefaultValue=#Panel-BGColor#
Command1=[!SetVariable Panel-BGColor "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Panel-BGColor [Input-1] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Update]

[Panel-BG1]
Meter=Image
ImageName=#@#Images\Panels\BG1.png
MeterStyle=SettingsStyle-CircleBG
Y=220
X=280
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Black"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "0,0,0,255" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG2]
Meter=Image
ImageName=#@#Images\Panels\BG2.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Dark"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "30,30,30,220" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG3]
Meter=Image
ImageName=#@#Images\Panels\BG3.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Translucent Dark"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "40,40,40,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG4]
Meter=Image
ImageName=#@#Images\Panels\BG4.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Clear"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "0,0,0,1" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG5]
Meter=Image
ImageName=#@#Images\Panels\BG5.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Translucent White"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "230,230,230,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG6]
Meter=Image
ImageName=#@#Images\Panels\BG6.png
MeterStyle=SettingsStyle-CircleBG
Y=240
X=280
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Light White"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "240,240,240,180" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG7]
Meter=Image
ImageName=#@#Images\Panels\BG7.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | White"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "255,255,255,255" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG8]
Meter=Image
ImageName=#@#Images\Panels\BG8.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Red"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "180,0,0,210" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG9]
Meter=Image
ImageName=#@#Images\Panels\BG9.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Green"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "0,180,0,210" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-BG10]
Meter=Image
ImageName=#@#Images\Panels\BG10.png
MeterStyle=SettingsStyle-CircleBG
MouseOverAction=[!SetOption Title3 "Text" "#VarBackgroundcolor# | Blue"][!Update]
MouseLeaveAction=[!SetOption Title3 "Text" "#VarBackgroundcolor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BGColor" "0,0,180,210" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]


;---- Bar Style ----

[Background4]
Meter=Shape
Shape=Rectangle 10,270,380,385,3 | Fill Color 50,50,50

[Title4]
Meter=String
MeterStyle=SettingsStyle-Text
Y=275
Text=#VarBarColor#

[Divider4]
Meter=Shape
Shape=Rectangle 12,290,375,2,0 | Fill Color 180,180,180

[Panel-Bar1]
Meter=Image
ImageName=#@#Images\Panels\Bar1.png
MeterStyle=SettingsStyle-CircleRL
Y=300
X=27
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Dark Green"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "0,255,30" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "0,140,30" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.50" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "60,60,60" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar2]
Meter=Image
ImageName=#@#Images\Panels\Bar2.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Dark Red-Green"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "0,210,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.38" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "80,80,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar3]
Meter=Image
ImageName=#@#Images\Panels\Bar3.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Light Red-Blue"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "0,0,200" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.54" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "210,210,210,150" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "80,80,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar4]
Meter=Image
ImageName=#@#Images\Panels\Bar4.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Dark White-Transparent"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "240,240,240" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "80,80,80" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.24" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "80,80,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar5]
Meter=Image
ImageName=#@#Images\Panels\Bar5.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Gold"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "1" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "226,176,7" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "30,30,30" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "0,0,0" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar6]
Meter=Image
ImageName=#@#Images\Panels\Bar6.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Light Aqua"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "29,224,172" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "68,71,153" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.50" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "255,255,255,200" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "255,255,255" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar7]
Meter=Image
ImageName=#@#Images\Panels\Bar7.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Dark Yellow-Blue"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "200,200,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "20,20,20" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "0,0,200" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.50" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "20,20,20" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar8]
Meter=Image
ImageName=#@#Images\Panels\Bar8.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Black-Green-Black"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "0,255,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.52" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "0,40,0" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar9]
Meter=Image
ImageName=#@#Images\Panels\Bar9.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Black-Blue-Black"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "0,0,125" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.52" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "60,60,60" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "0,0,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar10]
Meter=Image
ImageName=#@#Images\Panels\Bar10.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Forever Blue"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "0,0,255" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "0,0,125" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "72,236,255" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.64" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "210,210,210,140" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "0,0,80" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar11]
Meter=Image
ImageName=#@#Images\Panels\Bar11.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Pink-Grey"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "252,38,255" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "51,59,73" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.52" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "210,210,210,180" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "30,30,30" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar12]
Meter=Image
ImageName=#@#Images\Panels\Bar12.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Blue-Pink"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "20,20,255" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "252,38,255" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.60" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "60,0,60" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar13]
Meter=Image
ImageName=#@#Images\Panels\Bar13.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Orange"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "220,126,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.54" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "255,255,255,180" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "0,0,0" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]

[Panel-Bar14]
Meter=Image
ImageName=#@#Images\Panels\Bar14.png
MeterStyle=SettingsStyle-CircleRL
MouseOverAction=[!SetOption Title4 "Text" "#VarBarColor# | Dark Red"][!Update]
MouseLeaveAction=[!SetOption Title4 "Text" "#VarBarColor#"][!Update]
LeftMouseUpAction=[!WriteKeyValue Variables "Panel-BarFillStyle" "3" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "255,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "0.56" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "0,0,0" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "60,0,0" "#@#Variables.inc"][!Refresh][!RefreshGroup SYSMonitor-Panels]


;----


[Button7a]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=25
Y=330
ButtonCommand=[!WriteKeyValue Variables Panel-BarFillArc "0.52" "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillStyle "1" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button7aText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=5r
Text=#VarSingleColor#

[Button7b]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=75r
Y=-5r
ButtonCommand=[!WriteKeyValue Variables Panel-BarFillArc "0.52" "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillStyle "2" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button7bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Text=#VarDualColor#

[Button7c]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=75r
Y=-5r
ButtonCommand=[!WriteKeyValue Variables Panel-BarFillArc "0.52" "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillStyle "3" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
[Button7cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Text=#VarTripleColor#

[FillStyleOptionsDisplay]
Measure=Calc
Formula=#Panel-BarFillStyle#
IfCondition=FillStyleOptionsDisplay = 1
IfTrueAction=[!HideMeterGroup "FS2"][!HideMeterGroup "FS3"]
IfCondition2=FillStyleOptionsDisplay = 2
IfTrueAction2=[!ShowMeterGroup "FS2"][!HideMeterGroup "FS3"]
IfCondition3=FillStyleOptionsDisplay = 3
IfTrueAction3=[!ShowMeterGroup "FS2"][!ShowMeterGroup "FS3"]
UpdateDivier=10

[InputDescription-2]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBarColor# 1 (#VarUp#)
X=20
Y=380

[InputBG-2]
Meter=Shape
Shape=Rectangle 159,380,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-2 "ExecuteBatch 1-2"]
[InputText-2]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=380
Text=#Panel-BarFillColor1#
LeftMouseUpAction=[!CommandMeasure Input-2 "ExecuteBatch 1-2"]
[Input-2]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=381
H=13
FocusDismiss=0
DefaultValue=#Panel-BarFillColor1#
Command1=[!SetVariable Panel-BarFillColor1 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Panel-BarFillColor1 [Input-2] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]

[InputDescription-3]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBarColor# 2 (#VarMid#)
X=20
Y=420
Group=FS3

[InputBG-3]
Meter=Shape
Shape=Rectangle 159,420,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-3 "ExecuteBatch 1-2"]
Group=FS3

[InputText-3]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=420
Text=#Panel-BarFillColor2#
LeftMouseUpAction=[!CommandMeasure Input-3 "ExecuteBatch 1-2"]
Group=FS3

[Input-3]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=421
H=13
FocusDismiss=0
DefaultValue=#Panel-BarFillColor2#
Command1=[!SetVariable Panel-BarFillColor2 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Panel-BarFillColor2 [Input-3] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
Group=FS3

[InputDescription-4]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarBarColor# 3 (#VarDown#)
X=20
Y=460
Group=FS2

[InputBG-4]
Meter=Shape
Shape=Rectangle 159,460,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-4 "ExecuteBatch 1-2"]
Group=FS2

[InputText-4]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=460
Text=#Panel-BarFillColor3#
LeftMouseUpAction=[!CommandMeasure Input-4 "ExecuteBatch 1-2"]
Group=FS2

[Input-4]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=461
H=13
FocusDismiss=0
DefaultValue=#Panel-BarFillColor3#
Command1=[!SetVariable Panel-BarFillColor3 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Panel-BarFillColor3 [Input-4] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]
Group=FS2


[BarPreview]
Meter=Shape
Shape=Rectangle 255,365,20,125,3 | Fill LinearGradient RLPreview#Panel-BarFillStyle#
RLPreview=0 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor2# ; #Panel-BarFillArc# | #Panel-BarFillColor3# ; 0.0
RLPreview1=0 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor1# ; 0.0
RLPreview2=90 | #Panel-BarFillColor1# ; 1.0 |  #Panel-BarFillColor1# ; (#Panel-BarFillArc#+0.3) | #Panel-BarFillColor3# ; (#Panel-BarFillArc#-0.3) | #Panel-BarFillColor3# ; 0.0
RLPreview3=90 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor2# ; #Panel-BarFillArc# | #Panel-BarFillColor3# ; 0.0
DynamicVariables=1
UpdateDivier=5

[BarArcSliderLine]
Meter=Shape
Shape=Rectangle 305,380,6,90,3 | Fill Color 0,0,0 | StrokeWidth 1 | Stroke Color 180,180,180
Group=FS2

[BarArcButton]
Meter=Image
ImageName=#@#Images\General\Slider.png
SolidColor=0,0,0,1
X=298
Y=(465-#Panel-BarFillArc#*100)
LeftMouseDownAction=[!ShowMeterGroup DetectArc][!Update]
LeftMouseUpAction=[!HideMeterGroup DetectArc][!Refresh]
MouseLeaveAction=[!HideMeterGroup DetectArc][!Refresh]
Group=FS2

[ArcDetectStyle]
Meter=Image
Group=DetectArc
Solidcolor=255,255,255,0
X=300
W=16
H=2
Y=2r
Hidden=1
UpdateDivier=10

[ArcDetect09]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 375  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.90"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.90" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
Y=384
[ArcDetect88]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 377  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.88"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.88" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect86]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 379  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.86"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.86" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect84]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 381  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.84"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.84" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect82]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 383  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.82"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.82" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect80]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 385  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.80"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.80" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect78]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 387  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.78"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.78" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect76]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 389  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.76"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.76" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect74]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 391  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.74"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.74" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect72]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 393  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.72"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.72" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect70]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 395  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.70"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.70" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect68]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 397  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.68"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.68" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect66]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 399  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.66"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.66" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect64]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 401  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.64"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.64" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect62]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 403  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.62"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.62" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect60]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 405  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.60"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.60" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect58]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 407  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.58"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.58" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect56]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 409  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.56"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.56" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect54]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 411  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.54"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.54" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect52]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 413  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.52"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.52" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect50]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 415  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.50"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.50" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect48]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 417  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.48"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.48" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect46]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 419  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.46"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.46" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect44]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 421  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.44"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.44" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect42]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 423  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.42"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.42" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect40]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 425  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.40"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.40" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect38]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 427  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.38"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.38" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect36]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 429  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.36"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.36" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect34]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 431  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.34"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.34" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect32]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 433  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.32"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.32" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect30]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 435  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.30"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.30" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect28]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 437  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.28"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.28" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect26]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 439  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.26"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.26" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect24]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 441  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.24"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.24" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect22]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 443  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.22"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.22" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect20]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 445  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.20"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.20" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect18]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 447  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.18"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.18" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect16]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 449  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.16"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.16" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect14]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 451  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.14"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.14" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect12]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 453  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.12"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.12" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ArcDetect10]
Meter=Image
MeterStyle=ArcDetectStyle
MouseOverAction=[!MoveMeter 298 455  "BarArcButton"][!Redraw][!SetVariable Panel-BarFillArc "0.10"][!UpdateMeter "BarPreview"][!WriteKeyValue Variables Panel-BarFillArc "0.10" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]


[InputDescription-5]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarPanelBarBG#
X=20
Y=500

[InputBG-5]
Meter=Shape
Shape=Rectangle 159,500,90,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input-5 "ExecuteBatch 1-2"]
[InputText-5]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=500
Text=#Panel-BarColor#
LeftMouseUpAction=[!CommandMeasure Input-5 "ExecuteBatch 1-2"]
[Input-5]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=501
H=13
FocusDismiss=0
DefaultValue=#Panel-BarColor#
Command1=[!SetVariable Panel-BarColor "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Panel-BarColor [Input-5] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]

[InputDescription-6]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarFrame#
X=20
Y=520

[InputBG-6]
Meter=Shape
Shape=Rectangle 159,520,90,15,3 | Fill Color 0,0,0

LeftMouseUpAction=[!CommandMeasure Input-6 "ExecuteBatch 1-2"]
[InputText-6]
Meter=String
MeterStyle=SettingsStyle-Input
X=160
Y=520
Text=#Panel-StrokeColor#
LeftMouseUpAction=[!CommandMeasure Input-6 "ExecuteBatch 1-2"]
[Input-6]
Measure=Plugin
Plugin=InputText
FontSize=8
W=87
X=160
Y=521
H=13
FocusDismiss=0
DefaultValue=#Panel-StrokeColor#
Command1=[!SetVariable Panel-StrokeColor "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Panel-StrokeColor [Input-6] "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]

[BarPreview3]
Meter=Shape
Shape=Rectangle 255,500,125,33,0 | Fill LinearGradient RLPreview#Panel-BarFillStyle#
RLPreview=0 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor2# ; #Panel-BarFillArc# | #Panel-BarFillColor3# ; 0.0
RLPreview1=90 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor1# ; 0.0
RLPreview2=0 | #Panel-BarFillColor1# ; 1.0 |  #Panel-BarFillColor1# ; (#Panel-BarFillArc#+0.3) | #Panel-BarFillColor3# ; (#Panel-BarFillArc#-0.3) | #Panel-BarFillColor3# ; 0.0
RLPreview3=0 | #Panel-BarFillColor1# ; 1.0 | #Panel-BarFillColor2# ; #Panel-BarFillArc# | #Panel-BarFillColor3# ; 0.0
DynamicVariables=1

[BarPreview2]
Meter=Shape
Shape=Rectangle 255,500,125,33,3 | Fill Color #Panel-BarColor# | StrokeWidth 3 | Stroke Color #Panel-StrokeColor#
Shape2=Rectangle 285,503,2,27,3 | Fill Color #Panel-StrokeColor# | StrokeWidth 0
Shape3=Rectangle 315,503,2,27,3 | Fill Color #Panel-StrokeColor# | StrokeWidth 0
Shape4=Rectangle 345,503,2,27,3 | Fill Color #Panel-StrokeColor# | StrokeWidth 0
DynamicVariables=1


;---- Custom Presets ----

[ButtonCP1]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=350
Y=380
ToolTipTitle=Custom Preset
ToolTipText=LeftMouse: Load #1 #CRLF#RightMouse: Save to #1
ButtonCommand=[!WriteKeyValue Variables "Panel-FontColor" "#Panel-FontColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillStyle" "#Panel-BarFillStyle-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "#Panel-BarFillColor1-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "#Panel-BarFillColor2-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "#Panel-BarFillColor3-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "#Panel-BarFillArc-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "#Panel-BarColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "#Panel-StrokeColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGColor" "#Panel-BGColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGShadowColor" "#Panel-BGShadowColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideShadow" "#Panel-HideShadow-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideBGShadow" "#Panel-HideBGShadow-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-ButtonColor" "#Panel-ButtonColor-CP1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-Frame" "#Panel-Frame-CP1#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
RightMouseUpAction=[!WriteKeyValue Variables "Panel-FontColor-CP1" "#Panel-FontColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillStyle-CP1" "#Panel-BarFillStyle#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1-CP1" "#Panel-BarFillColor1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2-CP1" "#Panel-BarFillColor2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3-CP1" "#Panel-BarFillColor3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc-CP1" "#Panel-BarFillArc#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor-CP1" "#Panel-BarColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor-CP1" "#Panel-StrokeColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGColor-CP1" "#Panel-BGColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGShadowColor-CP1" "#Panel-BGShadowColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideShadow-CP1" "#Panel-HideShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideBGShadow-CP1" "#Panel-HideBGShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-ButtonColor-CP1" "#Panel-ButtonColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-Frame-CP1" "#Panel-Frame#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ButtonTextCP1]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=5r
Text=#1

[ButtonCP2]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=-12r
Y=30r
ToolTipTitle=Custom Preset
ToolTipText=LeftMouse: Load #2 #CRLF#RightMouse: Save to #2
ButtonCommand=[!WriteKeyValue Variables "Panel-FontColor" "#Panel-FontColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillStyle" "#Panel-BarFillStyle-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "#Panel-BarFillColor1-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "#Panel-BarFillColor2-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "#Panel-BarFillColor3-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "#Panel-BarFillArc-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "#Panel-BarColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "#Panel-StrokeColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGColor" "#Panel-BGColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGShadowColor" "#Panel-BGShadowColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideShadow" "#Panel-HideShadow-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideBGShadow" "#Panel-HideBGShadow-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-ButtonColor" "#Panel-ButtonColor-CP2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-Frame" "#Panel-Frame-CP2#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
RightMouseUpAction=[!WriteKeyValue Variables "Panel-FontColor-CP2" "#Panel-FontColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillStyle-CP2" "#Panel-BarFillStyle#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1-CP2" "#Panel-BarFillColor1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2-CP2" "#Panel-BarFillColor2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3-CP2" "#Panel-BarFillColor3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc-CP2" "#Panel-BarFillArc#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor-CP2" "#Panel-BarColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor-CP2" "#Panel-StrokeColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGColor-CP2" "#Panel-BGColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGShadowColor-CP2" "#Panel-BGShadowColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideShadow-CP2" "#Panel-HideShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideBGShadow-CP2" "#Panel-HideBGShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-ButtonColor-CP2" "#Panel-ButtonColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-Frame-CP2" "#Panel-Frame#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
[ButtonTextCP2]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=5r
Text=#2

[ButtonCP3]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn25x25.png
X=-12r
Y=30r
ToolTipTitle=Custom Preset
ToolTipText=LeftMouse: Load #3 #CRLF#RightMouse: Save to #3
ButtonCommand=[!WriteKeyValue Variables "Panel-FontColor" "#Panel-FontColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillStyle" "#Panel-BarFillStyle-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1" "#Panel-BarFillColor1-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2" "#Panel-BarFillColor2-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3" "#Panel-BarFillColor3-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc" "#Panel-BarFillArc-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor" "#Panel-BarColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor" "#Panel-StrokeColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGColor" "#Panel-BGColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGShadowColor" "#Panel-BGShadowColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideShadow" "#Panel-HideShadow-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideBGShadow" "#Panel-HideBGShadow-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-ButtonColor" "#Panel-ButtonColor-CP3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-Frame" "#Panel-Frame-CP3#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels]
RightMouseUpAction=[!WriteKeyValue Variables "Panel-FontColor-CP3" "#Panel-FontColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillStyle-CP3" "#Panel-BarFillStyle#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor1-CP3" "#Panel-BarFillColor1#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor2-CP3" "#Panel-BarFillColor2#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillColor3-CP3" "#Panel-BarFillColor3#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarFillArc-CP3" "#Panel-BarFillArc#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BarColor-CP3" "#Panel-BarColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-StrokeColor-CP3" "#Panel-StrokeColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGColor-CP3" "#Panel-BGColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-BGShadowColor-CP3" "#Panel-BGShadowColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideShadow-CP3" "#Panel-HideShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-HideBGShadow-CP3" "#Panel-HideBGShadow#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-ButtonColor-CP3" "#Panel-ButtonColor#" "#@#Variables.inc"][!WriteKeyValue Variables "Panel-Frame-CP3" "#Panel-Frame#" "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][ButtonTextCP3]
[ButtonTextCP3]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=12r
Y=5r
Text=#3


;---- Settings Import ----

[BackgroundImport]
Meter=Shape
Shape=Rectangle 10,665,380,70,3 | Fill Color 50,50,50

[TitleImport]
Meter=String
MeterStyle=SettingsStyle-Text
Y=670
Text=Import

[DividerImport]
Meter=Shape
Shape=Rectangle 12,685,375,2,0 | Fill Color 180,180,180

[ButtonImport]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25
Y=695
ButtonCommand=[!WriteKeyValue Variables Panel-FontColor #Circle-FontColor# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillStyle #Circle-RoundlineFillStyle# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillColor1 #Circle-RoundlineFillColor1# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillColor2 #Circle-RoundlineFillColor2# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillColor3 #Circle-RoundlineFillColor3# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarFillArc #Circle-RoundlineFillArc# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BarColor #Circle-BarColor# "#@#Variables.inc"][!WriteKeyValue Variables Panel-StrokeColor #Circle-DividerColor# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BGColor #Circle-BGColor# "#@#Variables.inc"][!WriteKeyValue Variables Panel-BGShadowColor #Circle-BGShadowColor# "#@#Variables.inc"][!WriteKeyValue Variables Panel-ButtonColor #Circle-ButtonColor# "#@#Variables.inc"][!WriteKeyValue Variables Panel-HideShadow #Circle-HideBGShadow# "#@#Variables.inc"][!RefreshGroup SYSMonitor-Panels][!Refresh]

[ButtonImportText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=175r
Text=#VarImportColorSettings#