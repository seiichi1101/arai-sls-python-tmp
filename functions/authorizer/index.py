def handler(event, context):
  print(event)
  return {"body": "hello!", "statusCode": 200}
