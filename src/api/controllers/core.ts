import { PassThrough } from "stream";
import path from "path";
import _ from "lodash";
import mime from "mime";
import axios, { AxiosRequestConfig, AxiosResponse } from "axios";
import crc32 from 'crc32';
import * as crypto from "crypto";
import APIException from "@/lib/exceptions/APIException.ts";
import EX from "@/api/consts/exceptions.ts";
import { createParser } from "eventsource-parser";
import logger from "@/lib/logger.ts";
import util from "@/lib/util.ts";

// 模型名称
const MODEL_NAME = "jimeng";
// 默认的AgentID
const DEFAULT_ASSISTANT_ID = "513695";
// 版本号
const VERSION_CODE = "5.8.0";
// 平台代码
const PLATFORM_CODE = "7";
// 设备ID
const DEVICE_ID = Math.random() * 999999999999999999 + 7000000000000000000;
// WebID
const WEB_ID = Math.random() * 999999999999999999 + 7000000000000000000;
// 用户ID
const USER_ID = util.uuid(false);
// 最大重试次数
const MAX_RETRY_COUNT = 3;
// 重试延迟
const RETRY_DELAY = 5000;
// 伪装headers
const FAKE_HEADERS = {
  Accept: "application/json, text/plain, */*",
  "Accept-Encoding": "gzip, deflate, br, zstd",
  "Accept-language": "zh-CN,zh;q=0.9",
  "Cache-control": "no-cache",
  "Last-event-id": "undefined",
  Appid: DEFAULT_ASSISTANT_ID,
  Appvr: VERSION_CODE,
  Origin: "https://jimeng.jianying.com",
  Pragma: "no-cache",
  Priority: "u=1, i",
  Referer: "https://jimeng.jianying.com",
  Pf: PLATFORM_CODE,
  "Sec-Ch-Ua":
    '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  "Sec-Ch-Ua-Mobile": "?0",
  "Sec-Ch-Ua-Platform": '"Windows"',
  "Sec-Fetch-Dest": "empty",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Site": "same-origin",
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
};
// 文件最大大小
const FILE_MAX_SIZE = 100 * 1024 * 1024;

/**
 * 获取缓存中的access_token
 *
 * 目前jimeng的access_token是固定的，暂无刷新功能
 *
 * @param refreshToken 用于刷新access_token的refresh_token
 */
export async function acquireToken(refreshToken: string): Promise<string> {
  return refreshToken;
}

/**
 * 生成cookie
 */
export function generateCookie(refreshToken: string) {
  return [
    `_tea_web_id=${WEB_ID}`,
    `is_staff_user=false`,
    `store-region=cn-gd`,
    `store-region-src=uid`,
    `sid_guard=${refreshToken}%7C${util.unixTimestamp()}%7C5184000%7CMon%2C+03-Feb-2025+08%3A17%3A09+GMT`,
    `uid_tt=${USER_ID}`,
    `uid_tt_ss=${USER_ID}`,
    `sid_tt=${refreshToken}`,
    `sessionid=${refreshToken}`,
    `sessionid_ss=${refreshToken}`,
    `sid_tt=${refreshToken}`
  ].join("; ");
}

/**
 * 获取积分信息
 *
 * @param refreshToken 用于刷新access_token的refresh_token
 */
export async function getCredit(refreshToken: string) {
  const {
    credit: { gift_credit, purchase_credit, vip_credit }
  } = await request("POST", "/commerce/v1/benefits/user_credit", refreshToken, {
    data: {},
    headers: {
      // Cookie: 'x-web-secsdk-uid=ef44bd0d-0cf6-448c-b517-fd1b5a7267ba; s_v_web_id=verify_m4b1lhlu_DI8qKRlD_7mJJ_4eqx_9shQ_s8eS2QLAbc4n; passport_csrf_token=86f3619c0c4a9c13f24117f71dc18524; passport_csrf_token_default=86f3619c0c4a9c13f24117f71dc18524; n_mh=9-mIeuD4wZnlYrrOvfzG3MuT6aQmCUtmr8FxV8Kl8xY; sid_guard=a7eb745aec44bb3186dbc2083ea9e1a6%7C1733386629%7C5184000%7CMon%2C+03-Feb-2025+08%3A17%3A09+GMT; uid_tt=59a46c7d3f34bda9588b93590cca2e12; uid_tt_ss=59a46c7d3f34bda9588b93590cca2e12; sid_tt=a7eb745aec44bb3186dbc2083ea9e1a6; sessionid=a7eb745aec44bb3186dbc2083ea9e1a6; sessionid_ss=a7eb745aec44bb3186dbc2083ea9e1a6; is_staff_user=false; sid_ucp_v1=1.0.0-KGRiOGY2ODQyNWU1OTk3NzRhYTE2ZmZhYmFjNjdmYjY3NzRmZGRiZTgKHgjToPCw0cwbEIXDxboGGJ-tHyAMMITDxboGOAhAJhoCaGwiIGE3ZWI3NDVhZWM0NGJiMzE4NmRiYzIwODNlYTllMWE2; ssid_ucp_v1=1.0.0-KGRiOGY2ODQyNWU1OTk3NzRhYTE2ZmZhYmFjNjdmYjY3NzRmZGRiZTgKHgjToPCw0cwbEIXDxboGGJ-tHyAMMITDxboGOAhAJhoCaGwiIGE3ZWI3NDVhZWM0NGJiMzE4NmRiYzIwODNlYTllMWE2; store-region=cn-gd; store-region-src=uid; user_spaces_idc={"7444764277623653426":"lf"}; ttwid=1|cxHJViEev1mfkjntdMziir8SwbU8uPNVSaeh9QpEUs8|1733966961|d8d52f5f56607427691be4ac44253f7870a34d25dd05a01b4d89b8a7c5ea82ad; _tea_web_id=7444838473275573797; fpk1=fa6c6a4d9ba074b90003896f36b6960066521c1faec6a60bdcb69ec8ddf85e8360b4c0704412848ec582b2abca73d57a; odin_tt=efe9dc150207879b88509e651a1c4af4e7ffb4cfcb522425a75bd72fbf894eda570bbf7ffb551c8b1de0aa2bfa0bd1be6c4157411ecdcf4464fcaf8dd6657d66',
      Referer: "https://jimeng.jianying.com/ai-tool/image/generate",
      // "Device-Time": 1733966964,
      // Sign: "f3dbb824b378abea7c03cbb152b3a365"
    }
  });
  logger.info(`\n积分信息: \n赠送积分: ${gift_credit}, 购买积分: ${purchase_credit}, VIP积分: ${vip_credit}`);
  return {
    giftCredit: gift_credit,
    purchaseCredit: purchase_credit,
    vipCredit: vip_credit,
    totalCredit: gift_credit + purchase_credit + vip_credit
  }
}

/**
 * 接收今日积分
 *
 * @param refreshToken 用于刷新access_token的refresh_token
 */
export async function receiveCredit(refreshToken: string) {
  logger.info("正在收取今日积分...")
  const { cur_total_credits, receive_quota  } = await request("POST", "/commerce/v1/benefits/credit_receive", refreshToken, {
    data: {
      time_zone: "Asia/Shanghai"
    },
    headers: {
      Referer: "https://jimeng.jianying.com/ai-tool/image/generate"
    }
  });
  logger.info(`\n今日${receive_quota}积分收取成功\n剩余积分: ${cur_total_credits}`);
  return cur_total_credits;
}

/**
 * 请求jimeng
 *
 * @param method 请求方法
 * @param uri 请求路径
 * @param params 请求参数
 * @param headers 请求头
 */
export async function request(
  method: string,
  uri: string,
  refreshToken: string,
  options: AxiosRequestConfig = {}
) {
  const token = await acquireToken(refreshToken);
  const deviceTime = util.unixTimestamp();
  const url = uri.includes('https://') ? uri : `https://jimeng.jianying.com${uri}`;
  const sign = util.md5(
    `9e2c|${uri.slice(-7)}|${PLATFORM_CODE}|${VERSION_CODE}|${deviceTime}||11ac`
  );
  let response
  if (uri.includes('https://')) {
    response = await axios.request({
      method,
      url,
      data: method.toUpperCase() !== 'GET' ? options.data : undefined,
      params: method.toUpperCase() === 'GET' ? { ...options.data, ...options.params } : options.params,
      headers: {
        ...FAKE_HEADERS,
        Cookie: generateCookie(token),
        ...options.headers,
      }
    })
  } else {
    response = await axios.request({
      method,
      url,
      params: {
        aid: DEFAULT_ASSISTANT_ID,
        device_platform: "web",
        region: "CN",
        web_id: WEB_ID,
        ...(options.params || {}),
      },
      headers: {
        ...FAKE_HEADERS,
        Cookie: generateCookie(token),
        "Device-Time": deviceTime,
        Sign: sign,
        "Sign-Ver": "1",
        ...(options.headers || {}),
      },
      timeout: 15000,
      validateStatus: () => true,
      ..._.omit(options, "params", "headers"),
    });
  }
  // 流式响应直接返回response
  if (options.responseType == "stream") return response;
  return checkResult(response);
}

/**
 * 预检查文件URL有效性
 *
 * @param fileUrl 文件URL
 */
export async function checkFileUrl(fileUrl: string) {
  if (util.isBASE64Data(fileUrl)) return;
  const result = await axios.head(fileUrl, {
    timeout: 15000,
    validateStatus: () => true,
  });
  if (result.status >= 400)
    throw new APIException(
      EX.API_FILE_URL_INVALID,
      `File ${fileUrl} is not valid: [${result.status}] ${result.statusText}`
    );
  // 检查文件大小
  if (result.headers && result.headers["content-length"]) {
    const fileSize = parseInt(result.headers["content-length"], 10);
    if (fileSize > FILE_MAX_SIZE)
      throw new APIException(
        EX.API_FILE_EXECEEDS_SIZE,
        `File ${fileUrl} is not valid`
      );
  }
}

/**
 * 上传文件
 *
 * @param fileUrl 文件URL
 * @param refreshToken 用于刷新access_token的refresh_token
 * @param isVideoImage 是否是用于视频图像
 */
export async function uploadImage(
  fileUrl: string,
  refreshToken: string,
  isVideoImage: boolean = false
): Promise<string> {
  // 预检查远程文件URL可用性
  await checkFileUrl(fileUrl);

  let filename, fileData, mimeType;
  // 如果是BASE64数据则直接转换为Buffer
  if (util.isBASE64Data(fileUrl)) {
    mimeType = util.extractBASE64DataFormat(fileUrl);
    const ext = mime.getExtension(mimeType);
    filename = `${util.uuid()}.${ext}`;
    fileData = Buffer.from(util.removeBASE64DataHeader(fileUrl), "base64");
  }
  // 下载文件到内存，如果您的服务器内存很小，建议考虑改造为流直传到下一个接口上，避免停留占用内存
  else {
    filename = path.basename(fileUrl);
    ({ data: fileData } = await axios.get(fileUrl, {
      responseType: "arraybuffer",
      // 100M限制
      maxContentLength: FILE_MAX_SIZE,
      // 60秒超时
      timeout: 60000,
    }));
  }

  try {
    mimeType = mimeType || mime.getType(filename);
    const imageCrc32 = crc32(fileData).toString(16);
    const uploadAuth = await getUploadAuth(refreshToken);
    const getUploadImageProofRequestParams = {
      Action: 'ApplyImageUpload',
      FileSize: fileData.length,
      ServiceId: 'tb4s082cfz',
      Version: '2018-08-01',
      s: util.generateRandomString({
        length: 10,
        charset: 'abcdefghijklmnopqrstuvwxyz0123456789'
      }),
    };
    // 获取图片上传请求头
    const requestHeadersInfo = await generateAuthorizationAndHeader(
      uploadAuth.access_key_id,
      uploadAuth.secret_access_key,
      uploadAuth.session_token,
      'cn-north-1',
      'imagex',
      'GET',
      getUploadImageProofRequestParams,
    );
    // 获取图片上传凭证
    const uploadImgRes = await request(
      'GET',
      'https://imagex.bytedanceapi.com/?' + httpBuildQuery(getUploadImageProofRequestParams),
      refreshToken,
      {
        params: {},
        data: {},
        headers: requestHeadersInfo
      }
    );

    if (uploadImgRes?.['Response  ']?.hasOwnProperty('Error')) {
      return;
    }

    const UploadAddress = uploadImgRes.Result.UploadAddress;
    // 用凭证拼接上传图片接口
    const uploadImgUrl = `https://${UploadAddress.UploadHosts[0]}/upload/v1/${UploadAddress.StoreInfos[0].StoreUri}`;
    // 上传图片
    const imageUploadRes = await uploadFile(
      uploadImgUrl,
      fileData,
      {
        Authorization: UploadAddress.StoreInfos[0].Auth,
        'Content-Crc32': imageCrc32,
        'Content-Type': 'application/octet-stream',
        // 'X-Storage-U': '3674996648187204',
      },
      'POST',
    );
    if (imageUploadRes.code !== 2000) {
      console.log(imageUploadRes.message);
      return;
    }
    const commitImgParams = {
      Action: 'CommitImageUpload',
      FileSize: fileData.length,
      ServiceId: 'tb4s082cfz',
      Version: '2018-08-01',
      // user_id: userUid,
    };

    const commitImgContent = {
      SessionKey: UploadAddress.SessionKey,
    };

    const commitImgHead = await generateAuthorizationAndHeader(
      uploadAuth.access_key_id,
      uploadAuth.secret_access_key,
      uploadAuth.session_token,
      'cn-north-1',
      'imagex',
      'POST',
      commitImgParams,
      commitImgContent,
    );
    // 提交图片上传
    const commitImg = await request(
      'POST',
      'https://imagex.bytedanceapi.com/?' + httpBuildQuery(commitImgParams),
      refreshToken,
      {
        params: {},
        data: commitImgContent,
        headers: {
          ...commitImgHead,
          'Content-Type': 'application/json',
        },
      }
    );

    if (commitImg['Response ']?.hasOwnProperty('Error')) {
      console.log(commitImg['Response  ']['Error']['Message']);
      return;
    }
    return commitImg.Result.Results[0].Uri
  } catch (error) {
    console.error('上传文件失败:', error);
  }
}

/**
 * 检查请求结果
 *
 * @param result 结果
 */
export function checkResult(result: AxiosResponse) {
  const { ret, errmsg, data } = result.data;
  if (!_.isFinite(Number(ret))) return result.data;
  if (ret === '0') return data;
  if (ret === '5000')
    throw new APIException(EX.API_IMAGE_GENERATION_INSUFFICIENT_POINTS, `[无法生成图像]: 即梦积分可能不足，${errmsg}`);
  throw new APIException(EX.API_REQUEST_FAILED, `[请求jimeng失败]: ${errmsg}`);
}

/**
 * Token切分
 *
 * @param authorization 认证字符串
 */
export function tokenSplit(authorization: string) {
  return authorization.replace("Bearer ", "").split(",");
}

/**
 * 获取Token存活状态
 */
export async function getTokenLiveStatus(refreshToken: string) {
  const result = await request(
    "POST",
    "/passport/account/info/v2",
    refreshToken,
    {
      params: {
        account_sdk_source: "web",
      },
    }
  );
  try {
    const { user_id } = checkResult(result);
    return !!user_id;
  } catch (err) {
    return false;
  }
}

export async function getUploadAuth(refreshToken: string): Promise<any> {
  return new Promise(async (resolve, reject) => {
    try {
      const authRes = await request(
        'POST',
        '/mweb/v1/get_upload_token?aid=513695&da_version=3.2.6&aigc_features=app_lip_sync',
        refreshToken,
        {
          params: {},
          data: { scene: 2 }
        }
      );
      if (
        !authRes
      ) {
        reject(authRes.errmsg ?? '获取上传凭证失败,账号可能已掉线!');
        return;
      }
      resolve(authRes);
    } catch (err) {
      console.error('获取上传凭证失败:', err);
      reject(err);
    }
  });
}

export function addHeaders(
  amzDate: string,
  sessionToken: string,
  requestBody: any,
): any {
  const headers = {
    'X-Amz-Date': amzDate,
    'X-Amz-Security-Token': sessionToken,
  };
  if (Object.keys(requestBody).length > 0) {
    // @ts-ignore
    headers['X-Amz-Content-Sha256'] = crypto
      .createHash('sha256')
      .update(JSON.stringify(requestBody))
      .digest('hex');
  }
  return headers;
}

export async function generateAuthorizationAndHeader(
  accessKeyID: string,
  secretAccessKey: string,
  sessionToken: string,
  region: string,
  service: string,
  requestMethod: string,
  requestParams: any,
  requestBody: any = {},
): Promise<any> {
  return new Promise((resolve) => {
    // 获取当前ISO时间
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';

    // 生成请求的Header
    const requestHeaders: Record<string, string> = addHeaders(
      amzDate,
      sessionToken,
      requestBody,
    )

    if (Object.keys(requestBody).length > 0) {
      // @ts-ignore
      requestHeaders['X-Amz-Content-Sha256'] = crypto
        .createHash('sha256')
        .update(JSON.stringify(requestBody))
        .digest('hex')
    }
    // 生成请求的Authorization
    const authorizationParams = [
      'AWS4-HMAC-SHA256 Credential=' + accessKeyID + '/' +
      credentialString(amzDate, region, service),
      'SignedHeaders=' + signedHeaders(requestHeaders),
      'Signature=' + signature(
        secretAccessKey,
        amzDate,
        region,
        service,
        requestMethod,
        requestParams,
        requestHeaders,
        requestBody,
      ),
    ];
    const authorization = authorizationParams.join(', ');

    // 返回Headers
    const headers: any = {};
    for (const key in requestHeaders) {
      headers[key] = requestHeaders[key];
    }
    headers['Authorization'] = authorization;
    resolve(headers);
  });
}

export function credentialString(
  amzDate: string,
  region: string,
  service: string,
): string {
  const credentialArr = [
    amzDate.substring(0, 8),
    region,
    service,
    'aws4_request',
  ];
  return credentialArr.join('/');
}

export function httpBuildQuery(params: any): string {
  const searchParams = new URLSearchParams();
  for (const key in params) {
    if (params?.hasOwnProperty(key)) {
      searchParams.append(key, params[key]);
    }
  }
  return searchParams.toString();
}

export function signedHeaders(requestHeaders: any): string {
  const headers: string[] = [];
  Object.keys(requestHeaders).forEach(function (r) {
    r = r.toLowerCase();
    headers.push(r);
  });
  return headers.sort().join(';');
}

export function canonicalString(
  requestMethod: string,
  requestParams: any,
  requestHeaders: any,
  requestBody: any,
): string {
  let canonicalHeaders: string[] = [];
  const headerKeys = Object.keys(requestHeaders).sort();
  for (let i = 0; i < headerKeys.length; i++) {
    canonicalHeaders.push(
      headerKeys[i].toLowerCase() + ':' + requestHeaders[headerKeys[i]],
    );
  }
  // @ts-ignore
  canonicalHeaders = canonicalHeaders.join('\n') + '\n';
  let body = '';
  if (Object.keys(requestBody).length > 0) {
    body = JSON.stringify(requestBody);
  }

  const canonicalStringArr = [
    requestMethod.toUpperCase(),
    '/',
    httpBuildQuery(requestParams),
    canonicalHeaders,
    signedHeaders(requestHeaders),
    crypto.createHash('sha256').update(body).digest('hex'),
  ];
  return canonicalStringArr.join('\n');
}

export function signature(
  secretAccessKey: string,
  amzDate: string,
  region: string,
  service: string,
  requestMethod: string,
  requestParams: any,
  requestHeaders: any,
  requestBody: any,
): string {
  // 生成signingKey
  const amzDay = amzDate.substring(0, 8);
  const kDate = crypto
    .createHmac('sha256', 'AWS4' + secretAccessKey)
    .update(amzDay)
    .digest();
  const kRegion = crypto.createHmac('sha256', new Uint8Array(kDate)).update(region).digest();
  const kService = crypto
    .createHmac('sha256', new Uint8Array(kRegion))
    .update(service)
    .digest();
  const signingKey = crypto
    .createHmac('sha256', new Uint8Array(kService))
    .update('aws4_request')
    .digest();

  // 生成StringToSign
  const stringToSignArr = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialString(amzDate, region, service),
    crypto
      .createHash('sha256')
      .update(
        canonicalString(
          requestMethod,
          requestParams,
          requestHeaders,
          requestBody,
        ),
      )
      .digest('hex'),
  ];
  const stringToSign = stringToSignArr.join('\n');
  return crypto
    .createHmac('sha256', new Uint8Array(signingKey))
    .update(stringToSign)
    .digest('hex');
}

export async function uploadFile(
  url: string,
  fileContent: Buffer,
  headers: any,
  refreshToken: string,
): Promise<any> {
  return new Promise(async (resolve, reject) => {
    const res = await request(
      'POST',
      url,
      refreshToken,
      {
        params: {},
        data: fileContent,
        headers
      }
    );
    resolve(res);
  });
}