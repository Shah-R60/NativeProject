import { Router } from "express";
import { upload } from "../middleware/multer.middleware.js";
import { verifyJWT } from "../middleware/auth.middleware.js";
import { publishTopic, getAllTopics, getNewestTopic, getTopicById, updateTopic, deleteTopic } from "../controller/topic.controller.js";
import { admin } from "../middleware/admin.middleware.js";

const router = Router();

// Create topic with multiple file uploads
router.route("/uploadTopic").post(
     upload.fields([
          {
               name:"TopicImage",
               maxCount:1
          },
          {
               name: 'descriptionMedia',
               maxCount: 10
          }
     ]),verifyJWT,admin,
     publishTopic
);

// Get all topics
router.route("/getAllTopics").get(verifyJWT,getAllTopics);

// Get newest topic
router.route("/getNewestTopic").get(verifyJWT,getNewestTopic);

// Get topic by ID
router.route("/:id").get(getTopicById);

// Update topic
router.route("/:id").put(
     upload.fields([
          {
               name:"TopicImage",
               maxCount:1
          },
          {
               name: 'descriptionMedia',
               maxCount: 10
          }
     ]),
     updateTopic
);

// Delete topic
router.route("/:id").delete(deleteTopic);

export default router;
