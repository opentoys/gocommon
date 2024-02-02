# 使用说明

### 数字转换
```go
DigitalConvert(1001)
// int 壹仟零壹
DigitalPrice(99999999999999.1)
// float64 玖拾玖兆玖仟玖佰玖拾玖亿玖仟玖佰玖拾玖万玖仟玖佰玖拾玖元零玖分叁厘柒毫伍丝
DigitalPrice("99999999999999.1")
// string 玖拾玖兆玖仟玖佰玖拾玖亿玖仟玖佰玖拾玖万玖仟玖佰玖拾玖元壹角
DigitalPrice("9999999999999999999999.112312312312312")
// string 玖拾玖垓玖仟玖佰玖拾玖京玖仟玖佰玖拾玖兆玖仟玖佰玖拾玖亿玖仟玖佰玖拾玖万玖仟玖佰玖拾玖元壹角壹分贰厘叁毫壹丝贰忽叁微壹纤贰沙叁尘壹埃贰渺叁漠壹贰
```

### 身份证号判断
```go
idcard.RegisterCode(map[string]string{"000000":"全国"})
idcard.ConcatCode(map[string]string{"000001":"全球"})

var no = idcard.Generate()

var id = idcard.IdCard(no)
id.Check()
// true
id.Parse()
// {152201 内蒙古自治区 兴安盟 乌兰浩特市 1981-02-04 女}
id.Age()
// 42
```

### 节假日判断
```go
holiday.RegisterDate(map[string]holiday.Holiday{"2024-02-01":{Name:"公司内部假日",Is: true}})

// today 2024-01-01
hiliday.Is(time.Now()) // false

// today 2024-02-01
hiliday.Is(time.Now()) // true
hiliday.Parse(time.Now()) // {Name:"公司内部假日",Is: true}

// today 2024-02-03
hiliday.Is(time.Now()) // true
hiliday.Parse(time.Now()) // {Name:"",Is: true}

holiday.ConcatDate(map[string]holiday.Holiday{"2024-02-01":{Name:"公司内部假日",Is: true})

// today 2024-01-01
hiliday.Is(time.Now()) // true
hiliday.Parse(time.Now()) // {Name:"元旦",Is: true}

// today 2024-02-01
hiliday.Is(time.Now()) // true
hiliday.Parse(time.Now()) // {Name:"公司内部假日",Is: true}

// today 2024-02-03
hiliday.Is(time.Now()) // true
hiliday.Parse(time.Now()) // {Name:"",Is: true}
```