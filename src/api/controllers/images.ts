import _ from "lodash";

import APIException from "@/lib/exceptions/APIException.ts";
import EX from "@/api/consts/exceptions.ts";
import util from "@/lib/util.ts";
import { getCredit, receiveCredit, request, uploadImage } from "./core.ts";
import logger from "@/lib/logger.ts";

const DEFAULT_ASSISTANT_ID = "513695";
export const DEFAULT_MODEL = "jimeng-3.0";
const DRAFT_VERSION = "3.0.2";
const MODEL_MAP = {
  "jimeng-3.0": "high_aes_general_v30l:general_v3.0_18b",
  "jimeng-2.1": "high_aes_general_v21_L:general_v2.1_L",
  "jimeng-2.0-pro": "high_aes_general_v20_L:general_v2.0_L",
  "jimeng-2.0": "high_aes_general_v20:general_v2.0",
  "jimeng-1.4": "high_aes_general_v14:general_v1.4",
  "jimeng-xl-pro": "text2img_xl_sft",
};

export function getModel(model: string) {
  return MODEL_MAP[model] || MODEL_MAP[DEFAULT_MODEL];
}

export async function generateImages(
  _model: string,
  prompt: string,
  {
    width = 1024,
    height = 1024,
    sampleStrength = 0.5,
    negativePrompt = "",
  }: {
    width?: number;
    height?: number;
    sampleStrength?: number;
    negativePrompt?: string;
  },
  refreshToken: string,
  image?: string
) {
  const model = getModel(_model);
  logger.info(`使用模型: ${_model} 映射模型: ${model} ${width}x${height} 精细度: ${sampleStrength}`);

  const { totalCredit } = await getCredit(refreshToken);
  if (totalCredit <= 0)
    await receiveCredit(refreshToken);

  let uploadID = null
  if (image) {
    uploadID = await uploadImage(image, refreshToken);
  }

  let abilities: Record<string, any> = {}
  if (image) {
    abilities = {
      "blend": {
        "type": "",
        "id": util.uuid(),
        "min_features": [],
        "core_param": {
          "type": "",
          "id": util.uuid(),
          "model": model,
          "prompt": '##' + prompt,
          "sample_strength": sampleStrength || 0.5,
          "image_ratio": 1,
          "large_image_info": {
            "type": "",
            "id": util.uuid(),
            "height": 1360,
            "width": 1360,
            "resolution_type": '1k'
          }
        },
        "ability_list": [
          {
            "type": "",
            "id": util.uuid(),
            "name": "byte_edit",
            "image_uri_list": [
              uploadID
            ],
            "image_list": [
              {
                "type": "image",
                "id": util.uuid(),
                "source_from": "upload",
                "platform_type": 1,
                "name": "",
                "image_uri": uploadID,
                "width": 0,
                "height": 0,
                "format": "",
                "uri": uploadID
              }
            ],
            "strength": 0.5
          }
        ],
        "history_option": {
          "type": "",
          "id": util.uuid(),
        },
        "prompt_placeholder_info_list": [
          {
            "type": "",
            "id": util.uuid(),
            "ability_index": 0
          }
        ],
        "postedit_param": {
          "type": "",
          "id": util.uuid(),
          "generate_type": 0
        }
      }
    }
  } else {
    abilities = {
      "generate": {
        "type": "",
        "id": util.uuid(),
        "core_param": {
          "type": "",
          "id": util.uuid(),
          "model": model,
          "prompt": prompt,
          "negative_prompt": negativePrompt || "",
          "seed": Math.floor(Math.random() * 100000000) + 2500000000,
          "sample_strength": sampleStrength || 0.5,
          "image_ratio": 1,
          "large_image_info": {
            "type": "",
            "id": util.uuid(),
            "height": height || 1024,
            "width": width || 1024,
            "resolution_type": '1k'
          }
        },
        "history_option": {
          "type": "",
          "id": util.uuid(),
        }
      }
    }
  }
  const componentId = util.uuid();
  const { aigc_data } = await request(
    "post",
    "/mweb/v1/aigc_draft/generate",
    refreshToken,
    {
      params: {
        babi_param: encodeURIComponent(
          JSON.stringify({
            scenario: "image_video_generation",
            feature_key: image ? "to_image_referenceimage_generate" : "aigc_to_image",
            feature_entrance: "to_image",
            feature_entrance_detail: image ? "to_image-referenceimage-byte_edit" : "to_image-" + model,
          })
        ),
      },
      data: {
        extend: {
          root_model: model,
          template_id: "",
        },
        submit_id: util.uuid(),
        metrics_extra: image ? undefined : JSON.stringify({
          templateId: "",
          generateCount: 1,
          promptSource: "custom",
          templateSource: "",
          lastRequestId: "",
          originRequestId: "",
        }),
        draft_content: JSON.stringify({
          type: "draft",
          id: util.uuid(),
          min_version: DRAFT_VERSION,
          is_from_tsn: true,
          version: DRAFT_VERSION,
          main_component_id: componentId,
          component_list: [
            {
              type: "image_base_component",
              id: componentId,
              min_version: DRAFT_VERSION,
              generate_type: image ? "blend" : "generate",
              aigc_mode: "workbench",
              abilities,
            },
          ],
        }),
        http_common_info: {
          aid: Number(DEFAULT_ASSISTANT_ID),
        },
      },
    }
  );
  const historyId = aigc_data.history_record_id;
  if (!historyId)
    throw new APIException(EX.API_IMAGE_GENERATION_FAILED, "记录ID不存在");
  let status = 20, failCode, item_list = [];
  while (status === 20) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const result = await request("post", "/mweb/v1/get_history_by_ids", refreshToken, {
      data: {
        history_ids: [historyId],
        image_info: {
          width: 2048,
          height: 2048,
          format: "webp",
          image_scene_list: [
            {
              scene: "smart_crop",
              width: 360,
              height: 360,
              uniq_key: "smart_crop-w:360-h:360",
              format: "webp",
            },
            {
              scene: "smart_crop",
              width: 480,
              height: 480,
              uniq_key: "smart_crop-w:480-h:480",
              format: "webp",
            },
            {
              scene: "smart_crop",
              width: 720,
              height: 720,
              uniq_key: "smart_crop-w:720-h:720",
              format: "webp",
            },
            {
              scene: "smart_crop",
              width: 720,
              height: 480,
              uniq_key: "smart_crop-w:720-h:480",
              format: "webp",
            },
            {
              scene: "smart_crop",
              width: 360,
              height: 240,
              uniq_key: "smart_crop-w:360-h:240",
              format: "webp",
            },
            {
              scene: "smart_crop",
              width: 240,
              height: 320,
              uniq_key: "smart_crop-w:240-h:320",
              format: "webp",
            },
            {
              scene: "smart_crop",
              width: 480,
              height: 640,
              uniq_key: "smart_crop-w:480-h:640",
              format: "webp",
            },
            {
              scene: "normal",
              width: 2400,
              height: 2400,
              uniq_key: "2400",
              format: "webp",
            },
            {
              scene: "normal",
              width: 1080,
              height: 1080,
              uniq_key: "1080",
              format: "webp",
            },
            {
              scene: "normal",
              width: 720,
              height: 720,
              uniq_key: "720",
              format: "webp",
            },
            {
              scene: "normal",
              width: 480,
              height: 480,
              uniq_key: "480",
              format: "webp",
            },
            {
              scene: "normal",
              width: 360,
              height: 360,
              uniq_key: "360",
              format: "webp",
            },
          ],
        },
        http_common_info: {
          aid: Number(DEFAULT_ASSISTANT_ID),
        },
      },
    });
    if (!result[historyId])
      throw new APIException(EX.API_IMAGE_GENERATION_FAILED, "记录不存在");
    status = result[historyId].status;
    failCode = result[historyId].fail_code;
    item_list = result[historyId].item_list;
  }
  if (status === 30) {
    if (failCode === '2038')
      throw new APIException(EX.API_CONTENT_FILTERED);
    else
      throw new APIException(EX.API_IMAGE_GENERATION_FAILED);
  }
  return item_list.map((item) => {
    if(!item?.image?.large_images?.[0]?.image_url)
      return item?.common_attr?.cover_url || null;
    return item.image.large_images[0].image_url;
  });
}

export default {
  generateImages,
};
