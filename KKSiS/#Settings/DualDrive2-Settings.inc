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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\DualDrive2" "DualDrive2.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\DualDrive2" "DualDrive2.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-DualDrive2Size" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-DualDrive2Size" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-DualDrive2Size" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"]
[Button2cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarBig#


;---- Options ----

[Background3]
Meter=Shape
Shape=Rectangle 230,35,160,170,3 | Fill Color 50,50,50

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
ButtonImage=#@#Images\Buttons\Hide#DualDrive2HideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2HideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#DualDrive2HideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2HideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#DualDrive2HideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2HideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#DualDrive2HideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2HideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2ColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2ColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2ColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2ColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[ButtonDescription34]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowPercent#
X=235
Y=20r
[Button34a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2ShowPercentage#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2ShowPercentage" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]
[Button34b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2ShowPercentage#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2ShowPercentage" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[ButtonDescription35]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowFreeSpace#
X=235
Y=20r
[Button35a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2ShowFreeSpace#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2ShowFreeSpace" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]
[Button35b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2ShowFreeSpace#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2ShowFreeSpace" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[ButtonDescription36]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarDriveSSDHDD#
X=235
Y=20r
[Button36a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2SSD#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2SSD" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]
[Button36b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#DualDrive2SSD#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "DualDrive2SSD" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]


;-- Technology -------------------------------------------------------------------------------- 

[BG3]
Meter=Shape
Shape=Rectangle 10,140,210,65,3 | Fill Color 50,50,50

[T3Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=145
Text=#VarTechnology#

[T3Divider]
Meter=Shape
Shape=Rectangle 12,160,206,2,0 | Fill Color 160,160,160

[Technology1Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=20
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "DualDrive2Format" "Windows" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2Format2" "" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2HideWindows" "0" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2HideHWiNFO" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[Technology1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=Windows

[Technology2Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=35r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "DualDrive2Format" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2Format2" "" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2HideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2HideHWiNFO" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[Technology2Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=HWiNFO 1

[Technology3Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=35r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "DualDrive2Format" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2Format2" "2" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2HideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "DualDrive2HideHWiNFO" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh]

[Technology3Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=HWiNFO 2


;---- Select Drives ----

[Select-BG]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50

[Select-Title]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=#VarSelectDisk#

[Select-Divider]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160

;---- Label Measures ----

[Measure_Drive1Label]
Measure				=FreeDiskSpace
Drive				=#Drive1Letter#:
Label				=1

[Measure_Drive2Label]
Measure				=FreeDiskSpace
Drive				=#Drive2Letter#:
Label				=1

[Measure_Drive3Label]
Measure				=FreeDiskSpace
Drive				=#Drive3Letter#:
Label				=1

[Measure_Drive4Label]
Measure				=FreeDiskSpace
Drive				=#Drive4Letter#:
Label				=1

[Measure_Drive5Label]
Measure				=FreeDiskSpace
Drive				=#Drive5Letter#:
Label				=1

[Measure_Drive6Label]
Measure				=FreeDiskSpace
Drive				=#Drive6Letter#:
Label				=1

[Measure_Drive7Label]
Measure				=FreeDiskSpace
Drive				=#Drive7Letter#:
Label				=1

[Measure_Drive8Label]
Measure				=FreeDiskSpace
Drive				=#Drive8Letter#:
Label				=1


[OptionA1_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=40	
Y=255
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive1Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA1_Text]
Meter=String
MeasureName=Measure_Drive1Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive1Letter#:\ %1

[OptionA2_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-18r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive2Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA2_Text]
Meter=String
MeasureName=Measure_Drive2Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive2Letter#:\ %1

[OptionA3_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-18r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive3Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA3_Text]
Meter=String
MeasureName=Measure_Drive3Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive3Letter#:\ %1

[OptionA4_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-18r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive4Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA4_Text]
Meter=String
MeasureName=Measure_Drive4Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive4Letter#:\ %1

[OptionA5_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-18r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive5Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA5_Text]
Meter=String
MeasureName=Measure_Drive5Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive5Letter#:\ %1

[OptionA6_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-18r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive6Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA6_Text]
Meter=String
MeasureName=Measure_Drive6Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive6Letter#:\ %1

[OptionA7_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-18r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive7Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA7_Text]
Meter=String
MeasureName=Measure_Drive7Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive7Letter#:\ %1

[OptionA8_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-18r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskALetter #Drive8Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionA8_Text]
Meter=String
MeasureName=Measure_Drive8Label
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=18r
Y=0r
Text=#Drive8Letter#:\ %1


[OptionB1_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=340	
Y=255
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive1Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB1_Text]
Meter=String
MeasureName=Measure_Drive1Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive1Letter#:\ %1

[OptionB2_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive2Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB2_Text]
Meter=String
MeasureName=Measure_Drive2Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive2Letter#:\ %1

[OptionB3_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive3Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB3_Text]
Meter=String
MeasureName=Measure_Drive3Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive3Letter#:\ %1

[OptionB4_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive4Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB4_Text]
Meter=String
MeasureName=Measure_Drive4Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive4Letter#:\ %1

[OptionB5_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive5Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB5_Text]
Meter=String
MeasureName=Measure_Drive5Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive5Letter#:\ %1

[OptionB6_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive6Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB6_Text]
Meter=String
MeasureName=Measure_Drive6Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive6Letter#:\ %1

[OptionB7_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive7Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB7_Text]
Meter=String
MeasureName=Measure_Drive7Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive7Letter#:\ %1

[OptionB8_Button]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=20r
DynamicVariables=1
ButtonCommand=[!WriteKeyValue Variables DualDrive2DiskBLetter #Drive8Letter# "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\DualDrive2"][!Refresh "#ROOTCONFIG#\Panels\DualDrive2"][!Refresh]

[OptionB8_Text]
Meter=String
MeasureName=Measure_Drive8Label
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#Drive8Letter#:\ %1

[SelectionA]
Measure=String
String=#DualDrive2DiskALetter#
IfMatch=#Drive1Letter#
IfMatchAction=[!SetOption OptionA1_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch2=#Drive2Letter#
IfMatchAction2=[!SetOption OptionA2_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch3=#Drive3Letter#
IfMatchAction3=[!SetOption OptionA3_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch4=#Drive4Letter#
IfMatchAction4=[!SetOption OptionA4_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch5=#Drive5Letter#
IfMatchAction5=[!SetOption OptionA5_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch6=#Drive6Letter#
IfMatchAction6=[!SetOption OptionA6_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch7=#Drive7Letter#
IfMatchAction7=[!SetOption OptionA7_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch8=#Drive8Letter#
IfMatchAction8=[!SetOption OptionA8_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[SelectionB]
Measure=String
String=#DualDrive2DiskBLetter#
IfMatch=#Drive1Letter#
IfMatchAction=[!SetOption OptionB1_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch2=#Drive2Letter#
IfMatchAction2=[!SetOption OptionB2_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch3=#Drive3Letter#
IfMatchAction3=[!SetOption OptionB3_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch4=#Drive4Letter#
IfMatchAction4=[!SetOption OptionB4_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch5=#Drive5Letter#
IfMatchAction5=[!SetOption OptionB5_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch6=#Drive6Letter#
IfMatchAction6=[!SetOption OptionB6_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch7=#Drive7Letter#
IfMatchAction7=[!SetOption OptionB7_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfMatch8=#Drive8Letter#
IfMatchAction8=[!SetOption OptionB8_Button ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=40
Y=450
W=300
Clipstring=2
Text=#VarDualDriveSelection#
