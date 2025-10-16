import random
from flask import Flask, request, Response

app = Flask(__name__)


class base64r:
    dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    shuffledDictionary = ""

    def __init__(self):
        self.shuffleDictionary()

    def shuffleDictionary(self):
        self.shuffledDictionary = ''.join(random.sample(self.dictionary, len(self.dictionary)))

    def doEncode(self, inputData, dictionary):
        bitString = "".join(list(map('{0:08b}'.format, inputData)))
        bitString = bitString + ("0" * (6 - len(bitString) % 6)) if len(bitString) % 6 != 0 else bitString

        output = ""
        for i in range(0, len(bitString), 6):
            output += dictionary[int(bitString[i:i + 6], 2)]

        output = output + ("=" * (3 - len(inputData) % 3)) if len(inputData) % 3 != 0 else output
        return output

    def doDecode(self, inputData, dictionary):
        inputData = inputData.strip("=")
        bitString = ""
        for character in inputData:
            bitString += '{0:06b}'.format(dictionary.index(character))
        bitString = bitString[:len(bitString) - len(bitString) % 8]
        output = b""
        for i in range(0, len(bitString), 8):
            output += int(bitString[i:i + 8], 2).to_bytes(1, "big")
        return output

    def encodeRandom(self, inputData):
        return self.doEncode(inputData, self.shuffledDictionary)

    def decodeRandom(self, inputData):
        return self.doDecode(inputData, self.shuffledDictionary)

    def encodeStandard(self, inputData):
        return self.doEncode(inputData, self.dictionary)

    def decodeStandard(self, inputData):
        return self.doDecode(inputData, self.dictionary)

b64 = base64r()
randomB64Dict = ''.join(random.sample(b64.dictionary, len(b64.dictionary)))


@app.route('/api/encode/standard/string', methods=["POST"])
def doEncodeString():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(b64.encodeStandard(request.data), mimetype="text/plain")

@app.route('/api/encode/standard/hex', methods=["POST"])
def doEncodeBytes():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(b64.encodeStandard(bytes.fromhex(request.data.decode().replace("\\x", ""))), mimetype="text/plain")

@app.route('/api/encode/random/string', methods=["POST"])
def doEncodeRandomString():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(b64.encodeRandom(request.data), mimetype="text/plain")

@app.route('/api/encode/random/hex', methods=["POST"])
def doEncodeRandomBytes():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(b64.encodeRandom(bytes.fromhex(request.data.decode().replace("\\x", ""))), mimetype="text/plain")

@app.route('/api/decode/standard/string', methods=["POST"])
def doDecodeString():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(b64.decodeStandard(request.data.decode()), mimetype="text/plain")

@app.route('/api/decode/standard/hex', methods=["POST"])
def doDecodeBytes():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(''.join(f'\\x{byte:02x}'for byte in b64.decodeStandard(request.data.decode())), mimetype="text/plain")

@app.route('/api/decode/random/string', methods=["POST"])
def doDecodeRandomString():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(b64.decodeRandom(request.data.decode()), mimetype="text/plain")

@app.route('/api/decode/random/hex', methods=["POST"])
def doDecodeRandomBytes():
    b64 = base64r()
    b64.shuffledDictionary = randomB64Dict
    return Response(''.join(f'\\x{byte:02x}'for byte in b64.decodeRandom(request.data.decode())), mimetype="text/plain")

@app.route("/api/check/random", methods=["POST"])
def checkDictionary():
    return Response(str(randomB64Dict == request.data.decode()), mimetype="text/plain")

@app.route("/swagger.json")
def getAPIDocs():
    resp = Response()
    resp.headers.set("Content-Disposition", 'attachment; filename="swagger.json"')
    resp.headers.set("Content-Type", "application/json")
    resp.data = """{
  "openapi": "3.1.0",
  "info": {
    "title": "Base64 - OpenAPI 3.1",
    "description":"This is a challenge using Base64 encoding. This API can perform Base64 encoding and decoding using both the standard character set, and a randomly ordered characterset. Your task is to recover the random character set used and submit it to the Check Solution API call to validate it.",
    "contact": {
      
    },

    "version":"1.0"
  },
  "servers": [
    {
      "url": """ + f"\"{request.url_root[:-1]}\"" + """
    }
  ],
  "tags": [
    {
      "name": "Encode",
      "description": "Base64 encode your data"
    },
    {
      "name": "Decode",
      "description": "Base64 decode your data"
    },
    {
      "name": "Check Solution",
      "description": "Check the submitted Base64 dictionary"
    }
  ],
  "paths": {
    "/api/encode/standard/string": {
      "post": {
        "tags": [
          "Encode"
        ],
        "summary": "Base64 encode a string using the default dictionary",
        "description": "Base64 encode a string using the default dictionary",
        "operationId": "encodeStandardString",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"This is a test"
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"VGhpcyBpcyBhIHRlc3Q="
              }
            }
          }
        }
      }
    },
    "/api/encode/standard/hex": {
      "post": {
        "tags": [
          "Encode"
        ],
        "summary": "Base64 encode bytes using the default dictionary",
        "description": "Base64 encode bytes using the default dictionary",
        "operationId": "encodeStandardHex",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"\\\\x54\\\\x68\\\\x69\\\\x73\\\\x20\\\\x69\\\\x73\\\\x20\\\\x61\\\\x20\\\\x74\\\\x65\\\\x73\\\\x74"
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"VGhpcyBpcyBhIHRlc3Q="
              }
            }
          }
        }
      }
    },
    "/api/encode/random/string": {
      "post": {
        "tags": [
          "Encode"
        ],
        "summary": "Base64 encode a string using a random dictionary",
        "description": "Base64 encode a string using a random dictionary",
        "operationId": "encodeRandomString",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"This is a test"
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"w7MQSeWQSeWMpF2nSxy="
              }
            }
          }
        }
      }
    },
    "/api/encode/random/hex": {
      "post": {
        "tags": [
          "Encode"
        ],
        "summary": "Base64 encode bytes using a random dictionary",
        "description": "Base64 encode bytes using a random dictionary",
        "operationId": "encodeRandomHex",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"\\\\x54\\\\x68\\\\x69\\\\x73\\\\x20\\\\x69\\\\x73\\\\x20\\\\x61\\\\x20\\\\x74\\\\x65\\\\x73\\\\x74"
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"w7MQSeWQSeWMpF2nSxy="
              }
            }
          }
        }
      }
    },
    "/api/decode/standard/string": {
      "post": {
        "tags": [
          "Decode"
        ],
        "summary": "Base64 decode a string using the default dictionary",
        "description": "Base64 decode a string using the default dictionary",
        "operationId": "decodeStandardString",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"VGhpcyBpcyBhIHRlc3Q="
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"This is a test"
              }
            }
          }
        }
      }
    },
    "/api/decode/standard/hex": {
      "post": {
        "tags": [
          "Decode"
        ],
        "summary": "Base64 decode bytes using the default dictionary",
        "description": "Base64 decode bytes using the default dictionary",
        "operationId": "decodeStandardHex",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"VGhpcyBpcyBhIHRlc3Q="
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"\\\\x54\\\\x68\\\\x69\\\\x73\\\\x20\\\\x69\\\\x73\\\\x20\\\\x61\\\\x20\\\\x74\\\\x65\\\\x73\\\\x74"
              }
            }
          }
        }
      }
    },
    "/api/decode/random/string": {
      "post": {
        "tags": [
          "Decode"
        ],
        "summary": "Base64 decode a string using a random dictionary",
        "description": "Base64 decode a string using a random dictionary",
        "operationId": "decodeRandomString",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"w7MQSeWQSeWMpF2nSxy="
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"This is a test"
              }
            }
          }
        }
      }
    },
    "/api/decode/random/hex": {
      "post": {
        "tags": [
          "Decode"
        ],
        "summary": "Base64 decode bytes using a random dictionary",
        "description": "Base64 decode bytes using a random dictionary",
        "operationId": "decodeRandomHex",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"w7MQSeWQSeWMpF2nSxy="
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"\\\\x54\\\\x68\\\\x69\\\\x73\\\\x20\\\\x69\\\\x73\\\\x20\\\\x61\\\\x20\\\\x74\\\\x65\\\\x73\\\\x74"
              }
            }
          }
        }
      }
    },
    "/api/check/random": {
      "post": {
        "tags":[
          "Check Solution"
        ],
        "summary": "Check if the supplied dictionary matches the one on the server",
        "description": "Check if the supplied dictionary matches the one on the server",
        "operationId": "checkRandom",
        "requestBody": {
          "content": {
            "text/plain": {
              "example":"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "Successful operation",
            "content": {
              "text/plain": {
                "example":"False"
              }
            }
          }
        }
      }
    }
  }
}"""
    return resp

@app.route("/")
def main():
    return Response(status=302, headers={"Location":"/static/swagger/index.html"})

if __name__ == '__main__':
    app.run()
